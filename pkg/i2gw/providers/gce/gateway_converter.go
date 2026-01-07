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

package gce

import (
	"fmt"
	"os"

	gkegatewayv1 "github.com/GoogleCloudPlatform/gke-gateway-api/apis/networking/v1"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/intermediate"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/notifications"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/common"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/gce/extensions"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

type irToGatewayResourcesConverter struct{}

// newIRToGatewayResourcesConverter returns an gce irToGatewayResourcesConverter instance.
func newIRToGatewayResourcesConverter() irToGatewayResourcesConverter {
	return irToGatewayResourcesConverter{}
}

func (c *irToGatewayResourcesConverter) irToGateway(ir intermediate.IR) (i2gw.GatewayResources, field.ErrorList) {
	gatewayResources, errs := common.ToGatewayResources(ir)
	if len(errs) != 0 {
		return i2gw.GatewayResources{}, errs
	}
	BuildGceGatewayExtensions(ir, &gatewayResources)
	BuildGceServiceExtensions(ir, &gatewayResources)
	BuildGceRouteExtensions(ir, &gatewayResources)
	return gatewayResources, nil
}

func BuildGceGatewayExtensions(ir intermediate.IR, gatewayResources *i2gw.GatewayResources) {
	for gwyKey, gatewayContext := range ir.Gateways {
		gwyPolicy := addGatewayPolicyIfConfigured(gwyKey, gatewayContext.ProviderSpecificIR)
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

func addGatewayPolicyIfConfigured(gatewayNamespacedName types.NamespacedName, gatewayIR intermediate.ProviderSpecificGatewayIR) *gkegatewayv1.GCPGatewayPolicy {
	if gatewayIR.Gce == nil {
		return nil
	}
	// If there is no specification related to GCPGatewayPolicy feature, return nil.
	if gatewayIR.Gce.SslPolicy == nil && gatewayIR.Gce.Tls == nil && gatewayIR.Gce.Logging == nil {
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
		gcpGatewayPolicy.Spec.Default.SslPolicy = extensions.BuildGCPGatewayPolicySecurityPolicyConfig(gatewayIR)
	}
	return &gcpGatewayPolicy
}

func BuildGceServiceExtensions(ir intermediate.IR, gatewayResources *i2gw.GatewayResources) {
	for svcKey, serviceIR := range ir.Services {
		bePolicy := addGCPBackendPolicyIfConfigured(svcKey, serviceIR)
		if bePolicy != nil {
			obj, err := i2gw.CastToUnstructured(bePolicy)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast GCPBackendPolicy to unstructured", bePolicy)
				continue
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}

		tlsPolicy := addBackendTLSPolicyIfConfigured(svcKey, serviceIR)
		if tlsPolicy != nil {
			obj, err := i2gw.CastToUnstructured(tlsPolicy)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast BackendTLSPolicy to unstructured", tlsPolicy)
				continue
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}

		hcPolicy := addHealthCheckPolicyIfConfigured(svcKey, serviceIR)
		if hcPolicy != nil {
			obj, err := i2gw.CastToUnstructured(hcPolicy)
			if err != nil {
				notify(notifications.ErrorNotification, "Failed to cast HealthCheckPolicy to unstructured", hcPolicy)
				continue
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *obj)
		}

		svc := addServiceAppProtocolIfConfigured(svcKey, serviceIR)
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

func addServiceAppProtocolIfConfigured(serviceNamespacedName types.NamespacedName, serviceIR intermediate.ProviderSpecificServiceIR) *corev1.Service {
	if serviceIR.Gce == nil || serviceIR.Gce.AppProtocol == nil || len(serviceIR.Gce.ServicePorts) == 0 {
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

	if *serviceIR.Gce.AppProtocol == "HTTPS" {
		if svc.Annotations == nil {
			svc.Annotations = make(map[string]string)
		}
		// Construct JSON for cloud.google.com/app-protocols
		// We need to map all ports to HTTPS if the annotation was global, or specific ports if we had that info.
		// The intermediate IR stores AppProtocol as a single string pointer for the service.
		// So we apply it to all ports we found.
		appProtocols := "{"
		first := true
		for _, port := range serviceIR.Gce.ServicePorts {
			if !first {
				appProtocols += ","
			}
			appProtocols += fmt.Sprintf("\"%d\":\"HTTPS\"", port)
			first = false
		}
		appProtocols += "}"
		svc.Annotations["cloud.google.com/app-protocols"] = appProtocols
	}

	for name, port := range serviceIR.Gce.ServicePorts {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name:        name,
			Port:        port,
			AppProtocol: serviceIR.Gce.AppProtocol,
		})
	}
	return svc
}

func BuildGceRouteExtensions(ir intermediate.IR, gatewayResources *i2gw.GatewayResources) {
	// No GCE specific route extensions for now as CORS is handled via standard filters.
}

func addGCPBackendPolicyIfConfigured(serviceNamespacedName types.NamespacedName, serviceIR intermediate.ProviderSpecificServiceIR) *LocalGCPBackendPolicy {
	if serviceIR.Gce == nil {
		return nil
	}
	// If there is no specification related to GCPBackendPolicy feature, return nil.
	if serviceIR.Gce.SessionAffinity == nil && serviceIR.Gce.SecurityPolicy == nil && serviceIR.Gce.Iap == nil && serviceIR.Gce.LocalityLbPolicy == nil {
		return nil
	}

	gcpBackendPolicy := LocalGCPBackendPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: serviceNamespacedName.Namespace,
			Name:      serviceNamespacedName.Name,
		},
		Spec: LocalGCPBackendPolicySpec{
			Default: &LocalGCPBackendPolicyConfig{},
			TargetRef: gatewayv1alpha2.NamespacedPolicyTargetReference{
				Group: "",
				Kind:  "Service",
				Name:  gatewayv1.ObjectName(serviceNamespacedName.Name),
			},
		},
		Status: map[string]interface{}{},
	}
	gcpBackendPolicy.SetGroupVersionKind(GCPBackendPolicyGVK)

	if serviceIR.Gce.SessionAffinity != nil {
		gcpBackendPolicy.Spec.Default.SessionAffinity = extensions.BuildGCPBackendPolicySessionAffinityConfig(serviceIR)
	}
	if serviceIR.Gce.SecurityPolicy != nil {
		gcpBackendPolicy.Spec.Default.SecurityPolicy = extensions.BuildGCPBackendPolicySecurityPolicyConfig(serviceIR)
		if serviceIR.Gce.SecurityPolicy.CreationCommand != "" {
			fmt.Fprintf(os.Stderr, "# Suggested Cloud Armor policy creation command for service %s/%s:\n%s\n\n", serviceNamespacedName.Namespace, serviceNamespacedName.Name, serviceIR.Gce.SecurityPolicy.CreationCommand)
		}
	}
	if serviceIR.Gce.Iap != nil {
		gcpBackendPolicy.Spec.Default.IAP = extensions.BuildGCPBackendPolicyIapConfig(serviceIR)
	}
	if serviceIR.Gce.LocalityLbPolicy != nil {
		gcpBackendPolicy.Spec.Default.LocalityLbPolicy = serviceIR.Gce.LocalityLbPolicy
	}

	return &gcpBackendPolicy
}

func addBackendTLSPolicyIfConfigured(serviceNamespacedName types.NamespacedName, serviceIR intermediate.ProviderSpecificServiceIR) *gatewayv1.BackendTLSPolicy {
	if serviceIR.Gce == nil || serviceIR.Gce.Tls == nil {
		return nil
	}

	policyName := fmt.Sprintf("tls-%s", serviceNamespacedName.Name)
	policy := common.CreateBackendTLSPolicy(serviceNamespacedName.Namespace, policyName, serviceNamespacedName.Name)
	
	// Ensure GVK is set for casting
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gatewayv1.GroupVersion.Group,
		Version: gatewayv1.GroupVersion.Version,
		Kind:    "BackendTLSPolicy",
	})

	if serviceIR.Gce.Tls.SecretName != "" {
		policy.Spec.Validation.CACertificateRefs = []gatewayv1.LocalObjectReference{
			{
				Group: "",
				Kind:  "Secret",
				Name:  gatewayv1.ObjectName(serviceIR.Gce.Tls.SecretName),
			},
		}
	}
	
	return &policy
}

func addHealthCheckPolicyIfConfigured(serviceNamespacedName types.NamespacedName, serviceIR intermediate.ProviderSpecificServiceIR) *gkegatewayv1.HealthCheckPolicy {
	if serviceIR.Gce == nil {
		return nil
	}
	// If there is no specification related to HealthCheckPolicy feature, return nil.
	if serviceIR.Gce.HealthCheck == nil {
		return nil
	}

	healthCheckPolicy := gkegatewayv1.HealthCheckPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: serviceNamespacedName.Namespace,
			Name:      serviceNamespacedName.Name,
		},
		Spec: gkegatewayv1.HealthCheckPolicySpec{
			Default: extensions.BuildHealthCheckPolicyConfig(serviceIR),
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
