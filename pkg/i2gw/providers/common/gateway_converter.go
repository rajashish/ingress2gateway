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

package common

import (
	"fmt"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/intermediate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ToGatewayResources converts the received intermediate.IR to i2gw.GatewayResource
// without taking into consideration any provider specific logic.
func ToGatewayResources(ir intermediate.IR) (i2gw.GatewayResources, field.ErrorList) {
	var errorList field.ErrorList
	gatewayResources := i2gw.GatewayResources{
		Gateways:           make(map[types.NamespacedName]gatewayv1.Gateway),
		HTTPRoutes:         make(map[types.NamespacedName]gatewayv1.HTTPRoute),
		GatewayClasses:     ir.GatewayClasses,
		GRPCRoutes:         ir.GRPCRoutes,
		TLSRoutes:          ir.TLSRoutes,
		TCPRoutes:          ir.TCPRoutes,
		UDPRoutes:          ir.UDPRoutes,
		BackendTLSPolicies: ir.BackendTLSPolicies,
		ReferenceGrants:    ir.ReferenceGrants,
	}
	for key, gatewayContext := range ir.Gateways {
		gatewayResources.Gateways[key] = gatewayContext.Gateway
	}
	for key, httpRouteContext := range ir.HTTPRoutes {
		gatewayResources.HTTPRoutes[key] = httpRouteContext.HTTPRoute
		hr := gatewayResources.HTTPRoutes[key]
		for i := range hr.Spec.Rules {
			hr.Spec.Rules[i].BackendRefs = removeBackendRefsDuplicates(hr.Spec.Rules[i].BackendRefs)
		}
		gatewayResources.HTTPRoutes[key] = hr
	}
	for key, serviceIR := range ir.Services {
		if svc := addServiceAppProtocolIfConfigured(key, serviceIR); svc != nil {
			unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(svc)
			if err != nil {
				errorList = append(errorList, field.Invalid(field.NewPath(key.Name), key.Name, fmt.Sprintf("failed to convert Service to unstructured: %v", err)))
				continue
			}
			gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, unstructured.Unstructured{Object: unstructuredObj})
		}
	}
	return gatewayResources, errorList
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
		// We need to map all ports to HTTPS if the annotation was global.
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
