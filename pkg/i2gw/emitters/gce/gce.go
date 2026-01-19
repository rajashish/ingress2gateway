/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gce_emitter

import (
	gkegatewayv1 "github.com/GoogleCloudPlatform/gke-gateway-api/apis/networking/v1"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitters/utils"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/notifications"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

var (
	GCPBackendPolicyGVK = schema.GroupVersionKind{
		Group:   "networking.gke.io",
		Version: "v1",
		Kind:    "GCPBackendPolicy",
	}

	GCPGatewayPolicyGVK = schema.GroupVersionKind{
		Group:   "networking.gke.io",
		Version: "v1",
		Kind:    "GCPGatewayPolicy",
	}

	HealthCheckPolicyGVK = schema.GroupVersionKind{
		Group:   "networking.gke.io",
		Version: "v1",
		Kind:    "HealthCheckPolicy",
	}
)

func init() {
	i2gw.EmitterConstructorByName["gce"] = NewEmitter
}

type Emitter struct{}

func NewEmitter(_ *i2gw.EmitterConf) i2gw.Emitter {
	return &Emitter{}
}

func (c *Emitter) Emit(ir emitterir.EmitterIR) (i2gw.GatewayResources, field.ErrorList) {
	gatewayResources, errs := utils.ToGatewayResources(ir)
	if len(errs) != 0 {
		return i2gw.GatewayResources{}, errs
	}
	buildGceGatewayExtensions(ir, &gatewayResources)
	buildGceServiceExtensions(ir, &gatewayResources)
	buildGceHTTPRouteExtensions(ir, &gatewayResources)
	return gatewayResources, nil
}

func buildGceHTTPRouteExtensions(ir emitterir.EmitterIR, gatewayResources *i2gw.GatewayResources) {
	for _, gatewayContext := range ir.Gateways {
		if gatewayContext.Gce != nil && gatewayContext.Gce.EnableHTTPSRedirect {
			applyHTTPSRedirect(&gatewayContext, gatewayResources)
		}
	}
}

func applyHTTPSRedirect(gatewayContext *emitterir.GatewayContext, gatewayResources *i2gw.GatewayResources) {
	newRoutes := make(map[types.NamespacedName]gatewayv1.HTTPRoute)

	// Iterate over generated HTTPRoutes
	for key, route := range gatewayResources.HTTPRoutes {
		// Check if this route is attached to the Gateway we are interested in
		for i, parentRef := range route.Spec.ParentRefs {
			if string(parentRef.Name) == gatewayContext.Name && (parentRef.Namespace == nil || string(*parentRef.Namespace) == gatewayContext.Namespace) {
				
				// If port is nil (all listeners) or 80 (HTTP)
				if parentRef.Port == nil || *parentRef.Port == 80 {
					// 1. Create the redirect route for port 80
					redirectRoute := route.DeepCopy()
					redirectRoute.Name = route.Name + "-redirect"
					
					// Set parentRef to port 80 explicitly
					redirectRoute.Spec.ParentRefs = []gatewayv1.ParentReference{
						{
							Group: parentRef.Group,
							Kind:  parentRef.Kind,
							Namespace: parentRef.Namespace,
							Name:  parentRef.Name,
							Port:  ptrTo(gatewayv1.PortNumber(80)),
						},
					}

					redirectRoute.Spec.Rules = []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestRedirect,
									RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
										Scheme:     ptrTo("https"),
										StatusCode: ptrTo(301),
										Port:       ptrTo(gatewayv1.PortNumber(443)),
									},
								},
							},
						},
					}
					newRoutes[types.NamespacedName{Namespace: redirectRoute.Namespace, Name: redirectRoute.Name}] = *redirectRoute

					// 2. Modify the original route to be on port 443 only
					// We need to modify the specific parentRef in the slice
					route.Spec.ParentRefs[i].Port = ptrTo(gatewayv1.PortNumber(443))
					gatewayResources.HTTPRoutes[key] = route
				}
			}
		}
	}

	for k, v := range newRoutes {
		gatewayResources.HTTPRoutes[k] = v
	}
}

func ptrTo[T any](v T) *T {
	return &v
}

func buildGceGatewayExtensions(ir emitterir.EmitterIR, gatewayResources *i2gw.GatewayResources) {
	for gwyKey, gatewayContext := range ir.Gateways {
		gwyPolicy := addGatewayPolicyIfConfigured(gwyKey, &gatewayContext)
		if gwyPolicy == nil {
			continue
		}
		obj, err := i2gw.CastToUnstructured(gwyPolicy)
		if err != nil {
			notify(notifications.ErrorNotification, "Failed to cast GCPGatewayPolicy to unstructured", gwyPolicy)
			continue
		}
		gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
	}
}

func addGatewayPolicyIfConfigured(gatewayNamespacedName types.NamespacedName, gatewayIR *emitterir.GatewayContext) *gkegatewayv1.GCPGatewayPolicy {
	if gatewayIR == nil || gatewayIR.Gce == nil {
		return nil
	}
	// If there is no specification related to GCPGatewayPolicy feature, return nil.
	if gatewayIR.Gce.SslPolicy == nil {
		return nil
	}
	gcpGatewayPolicy := gkegatewayv1.GCPGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gatewayNamespacedName.Namespace,
			Name:      gatewayNamespacedName.Name,
		},
		Spec: gkegatewayv1.GCPGatewayPolicySpec{
			Default: &gkegatewayv1.GCPGatewayPolicyConfig{},
			TargetRef: gatewayv1alpha2.NamespacedPolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "Gateway",
				Name:  gatewayv1.ObjectName(gatewayNamespacedName.Name),
			},
		},
	}
	gcpGatewayPolicy.SetGroupVersionKind(GCPGatewayPolicyGVK)
	if gatewayIR.Gce.SslPolicy != nil {
		gcpGatewayPolicy.Spec.Default.SslPolicy = BuildGCPGatewayPolicySecurityPolicyConfig(gatewayIR)
	}
	return &gcpGatewayPolicy
}

func buildGceServiceExtensions(ir emitterir.EmitterIR, gatewayResources *i2gw.GatewayResources) {
	for svcKey, gceServiceIR := range ir.GceServices {
		bePolicy := addGCPBackendPolicyIfConfigured(svcKey, gceServiceIR)
		if bePolicy != nil {
			obj, err := i2gw.CastToUnstructured(bePolicy)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast GCPBackendPolicy to unstructured", bePolicy)
				continue
			}
			if gceServiceIR.LocalityLbPolicy != nil {
				if err := unstructured.SetNestedField(obj.Object, *gceServiceIR.LocalityLbPolicy, "spec", "default", "localityLbPolicy"); err != nil {
					notify(notifications.ErrorNotification, "Failed to set localityLbPolicy", bePolicy)
				}
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}

		hcPolicy := addHealthCheckPolicyIfConfigured(svcKey, &gceServiceIR)
		if hcPolicy != nil {
			obj, err := i2gw.CastToUnstructured(hcPolicy)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast HealthCheckPolicy to unstructured", hcPolicy)
				continue
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}
	}
}

func addGCPBackendPolicyIfConfigured(serviceNamespacedName types.NamespacedName, gceServiceIR gce.ServiceIR) *gkegatewayv1.GCPBackendPolicy {
	// If there is no specification related to GCPBackendPolicy feature, return nil.
	if gceServiceIR.SessionAffinity == nil && gceServiceIR.SecurityPolicy == nil && gceServiceIR.LocalityLbPolicy == nil && gceServiceIR.IAP == nil {
		return nil
	}

	gcpBackendPolicy := gkegatewayv1.GCPBackendPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: serviceNamespacedName.Namespace,
			Name:      serviceNamespacedName.Name,
		},
		Spec: gkegatewayv1.GCPBackendPolicySpec{
			Default: &gkegatewayv1.GCPBackendPolicyConfig{},
			TargetRef: gatewayv1alpha2.NamespacedPolicyTargetReference{
				Group: "",
				Kind:  "Service",
				Name:  gatewayv1.ObjectName(serviceNamespacedName.Name),
			},
		},
	}
	gcpBackendPolicy.SetGroupVersionKind(GCPBackendPolicyGVK)

	if gceServiceIR.SessionAffinity != nil {
		gcpBackendPolicy.Spec.Default.SessionAffinity = BuildGCPBackendPolicySessionAffinityConfig(gceServiceIR)
	}
	if gceServiceIR.SecurityPolicy != nil {
		gcpBackendPolicy.Spec.Default.SecurityPolicy = BuildGCPBackendPolicySecurityPolicyConfig(gceServiceIR)
	}
	if gceServiceIR.IAP != nil {
		gcpBackendPolicy.Spec.Default.IAP = BuildGCPBackendPolicyIAPConfig(gceServiceIR)
	}

	return &gcpBackendPolicy
}

func addHealthCheckPolicyIfConfigured(serviceNamespacedName types.NamespacedName, gceServiceIR *gce.ServiceIR) *gkegatewayv1.HealthCheckPolicy {
	if gceServiceIR == nil {
		return nil
	}
	// If there is no specification related to HealthCheckPolicy feature, return nil.
	if gceServiceIR.HealthCheck == nil {
		return nil
	}

	healthCheckPolicy := gkegatewayv1.HealthCheckPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: serviceNamespacedName.Namespace,
			Name:      serviceNamespacedName.Name,
		},
		Spec: gkegatewayv1.HealthCheckPolicySpec{
			Default: BuildHealthCheckPolicyConfig(gceServiceIR),
			TargetRef: gatewayv1alpha2.NamespacedPolicyTargetReference{
				Group: "",
				Kind:  "Service",
				Name:  gatewayv1.ObjectName(serviceNamespacedName.Name),
			},
		},
	}
	healthCheckPolicy.SetGroupVersionKind(HealthCheckPolicyGVK)
	return &healthCheckPolicy
}
