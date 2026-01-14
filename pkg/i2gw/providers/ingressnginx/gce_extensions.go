/*
Copyright 2026 The Kubernetes Authors.

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
	"strconv"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	providerir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func gceFeature(ingresses []networkingv1.Ingress, _ map[types.NamespacedName]map[string]int32, ir *providerir.ProviderIR) field.ErrorList {
	var errs field.ErrorList

	for _, ingress := range ingresses {
		processSessionAffinity(ingress, ir)
	}

	return errs
}

func processSessionAffinity(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	affinity, ok := ingress.Annotations[AffinityAnnotation]
	if !ok || affinity != "cookie" {
		return
	}

	affinityType := "GENERATED_COOKIE"
	var ttl *int64
	if val, ok := ingress.Annotations[SessionCookieExpiresAnnotation]; ok {
		if seconds, err := strconv.ParseInt(val, 10, 64); err == nil {
			ttl = &seconds
		}
	}

	var localityLbPolicy *string
	if val, ok := ingress.Annotations[AffinityModeAnnotation]; ok {
		if val == "persistent" {
			policy := "MAGLEV"
			localityLbPolicy = &policy
		}
	}

	updateService := func(svcName types.NamespacedName) {
		if ir.Services == nil {
			ir.Services = make(map[types.NamespacedName]providerir.ProviderSpecificServiceIR)
		}
		svcIR, ok := ir.Services[svcName]
		if !ok {
			svcIR = providerir.ProviderSpecificServiceIR{}
		}
		if svcIR.Gce == nil {
			svcIR.Gce = &gce.ServiceIR{}
		}
		svcIR.Gce.SessionAffinity = &gce.SessionAffinityConfig{
			AffinityType: affinityType,
			CookieTTLSec: ttl,
		}
		if localityLbPolicy != nil {
			svcIR.Gce.LocalityLbPolicy = localityLbPolicy
		}
		ir.Services[svcName] = svcIR
	}

	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		updateService(types.NamespacedName{
			Namespace: ingress.Namespace,
			Name:      ingress.Spec.DefaultBackend.Service.Name,
		})
	}

	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				updateService(types.NamespacedName{
					Namespace: ingress.Namespace,
					Name:      path.Backend.Service.Name,
				})
			}
		}
	}
}
