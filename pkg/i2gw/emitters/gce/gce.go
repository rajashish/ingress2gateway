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
	"fmt"

	gkegatewayv1 "github.com/GoogleCloudPlatform/gke-gateway-api/apis/networking/v1"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitters/utils"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/notifications"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	return gatewayResources, nil
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
	// SslPolicy support deferred to later PR
	return &gcpGatewayPolicy
}

func buildGceServiceExtensions(ir emitterir.EmitterIR, gatewayResources *i2gw.GatewayResources) {
	for svcKey, gceServiceIR := range ir.GceServices {
		hcPolicy := addHealthCheckPolicyIfConfigured(svcKey, &gceServiceIR)
		if hcPolicy != nil {
			obj, err := i2gw.CastToUnstructured(hcPolicy)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast HealthCheckPolicy to unstructured", hcPolicy)
				continue
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}

		svc := addServiceAppProtocolIfConfigured(svcKey, gceServiceIR)
		if svc != nil {
			obj, err := i2gw.CastToUnstructured(svc)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast Service to unstructured", svc)
				continue
			}

			// Clean up targetPort if 0 to avoid overwriting existing configuration
			if spec, ok := obj.Object["spec"].(map[string]interface{}); ok {
				if ports, ok := spec["ports"].([]interface{}); ok {
					for _, p := range ports {
						if portMap, ok := p.(map[string]interface{}); ok {
							if tp, ok := portMap["targetPort"]; ok {
								if tpInt, ok := tp.(int64); ok && tpInt == 0 {
									delete(portMap, "targetPort")
								}
							}
						}
					}
				}
			}

			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}
	}
}

func addServiceAppProtocolIfConfigured(serviceNamespacedName types.NamespacedName, serviceIR gce.ServiceIR) *corev1.Service {
	if serviceIR.AppProtocol == nil || len(serviceIR.ServicePorts) == 0 {
		return nil
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceNamespacedName.Name,
			Namespace: serviceNamespacedName.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{},
		},
	}
	svc.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"})

	if *serviceIR.AppProtocol != "" {
		if svc.Annotations == nil {
			svc.Annotations = make(map[string]string)
		}
		// Construct JSON for cloud.google.com/app-protocols
		appProtocols := "{"
		first := true
		for _, port := range serviceIR.ServicePorts {
			if !first {
				appProtocols += ","
			}
			appProtocols += fmt.Sprintf("\"%d\":\"%s\"", port, *serviceIR.AppProtocol)
			first = false
		}
		appProtocols += "}"
		svc.Annotations["cloud.google.com/app-protocols"] = appProtocols
	}

	for name, port := range serviceIR.ServicePorts {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name:        name,
			Port:        port,
			AppProtocol: serviceIR.AppProtocol,
		})
	}
	return svc
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
			TargetRef: gatewayv1alpha2.NamespacedPolicyTargetReference{
				Group: "",
				Kind:  "Service",
				Name:  gatewayv1.ObjectName(serviceNamespacedName.Name),
			},
		},
	}
	
	if gceServiceIR.HealthCheck.Type != nil {
		t := *gceServiceIR.HealthCheck.Type
		if t == "HTTP2" {
			healthCheckPolicy.Spec.Default = &gkegatewayv1.HealthCheckPolicyConfig{
				Config: &gkegatewayv1.HealthCheck{
					Type: gkegatewayv1.HTTP2,
					HTTP2: &gkegatewayv1.HTTP2HealthCheck{},
				},
			}
		} else if t == "HTTPS" {
			healthCheckPolicy.Spec.Default = &gkegatewayv1.HealthCheckPolicyConfig{
				Config: &gkegatewayv1.HealthCheck{
					Type: gkegatewayv1.HTTPS,
					HTTPS: &gkegatewayv1.HTTPSHealthCheck{},
				},
			}
		}
	}

	healthCheckPolicy.SetGroupVersionKind(HealthCheckPolicyGVK)
	return &healthCheckPolicy
}