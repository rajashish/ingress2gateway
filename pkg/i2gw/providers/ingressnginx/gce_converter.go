/*
Copyright 2025 The Kubernetes Authors.

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

package ingressnginx

import (
	"fmt"
	"strings"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	providerir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	annotationPrefix          = "nginx.ingress.kubernetes.io"
	annotationBackendProtocol = annotationPrefix + "/backend-protocol"
)

func gceFeature(ingressList []networkingv1.Ingress, servicePorts map[types.NamespacedName]map[string]int32, ir *providerir.ProviderIR) field.ErrorList {
	var errs field.ErrorList

	for _, ingress := range ingressList {
		processServiceAnnotations(ingress, ir, servicePorts)
		processGatewayAnnotations(ingress, ir)
	}

	return errs
}

func processServiceAnnotations(ingress networkingv1.Ingress, ir *providerir.ProviderIR, servicePorts map[types.NamespacedName]map[string]int32) {
	services := getReferencedServices(ingress)

	for _, svcName := range services {
		svcKey := types.NamespacedName{Namespace: ingress.Namespace, Name: svcName}
		serviceIR, ok := ir.Services[svcKey]
		if !ok {
			serviceIR = providerir.ProviderSpecificServiceIR{}
		}
		if serviceIR.Gce == nil {
			serviceIR.Gce = &gce.ServiceIR{}
		}

		// Backend Protocol
		if val, ok := ingress.Annotations[annotationBackendProtocol]; ok {
			upperVal := strings.ToUpper(val)
			if upperVal == "HTTPS" || upperVal == "HTTP2" || upperVal == "GRPC" {
				appProtocol := upperVal
				if upperVal == "GRPC" {
					appProtocol = "HTTP2"
				}

				serviceIR.Gce.AppProtocol = &appProtocol

				if serviceIR.Gce.HealthCheck == nil {
					serviceIR.Gce.HealthCheck = &gce.HealthCheckConfig{}
				}
				serviceIR.Gce.HealthCheck.Type = &appProtocol

				if serviceIR.Gce.ServicePorts == nil {
					serviceIR.Gce.ServicePorts = make(map[string]int32)
				}
				if ports, ok := servicePorts[svcKey]; ok {
					for name, port := range ports {
						serviceIR.Gce.ServicePorts[name] = port
					}
				} else {
					extracted := getPortsForService(ingress, svcName)
					for _, p := range extracted {
						found := false
						for _, existing := range serviceIR.Gce.ServicePorts {
							if existing == p {
								found = true
								break
							}
						}
						if !found {
							serviceIR.Gce.ServicePorts[fmt.Sprintf("port-%d", p)] = p
						}
					}
				}
			}
		}

		ir.Services[svcKey] = serviceIR
	}
}

func processGatewayAnnotations(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	ingressClass := ingress.Spec.IngressClassName
	if ingressClass == nil {
		if val, ok := ingress.Annotations["kubernetes.io/ingress.class"]; ok {
			ingressClass = &val
		}
	}

	if ingressClass != nil {
		for name, gw := range ir.Gateways {
			if name.Name == *ingressClass || string(gw.Spec.GatewayClassName) == *ingressClass {
				gw.Spec.GatewayClassName = gatewayv1.ObjectName("gke-l7-global-external-managed")
				ir.Gateways[name] = gw
			}
		}
	}
}

func getReferencedServices(ingress networkingv1.Ingress) []string {
	var services []string
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		services = append(services, ingress.Spec.DefaultBackend.Service.Name)
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					services = append(services, path.Backend.Service.Name)
				}
			}
		}
	}
	return services
}

func getPortsForService(ingress networkingv1.Ingress, serviceName string) []int32 {
	var ports []int32
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		if ingress.Spec.DefaultBackend.Service.Name == serviceName {
			if ingress.Spec.DefaultBackend.Service.Port.Number > 0 {
				ports = append(ports, ingress.Spec.DefaultBackend.Service.Port.Number)
			}
		}
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil && path.Backend.Service.Name == serviceName {
					if path.Backend.Service.Port.Number > 0 {
						ports = append(ports, path.Backend.Service.Port.Number)
					}
				}
			}
		}
	}
	return ports
}
