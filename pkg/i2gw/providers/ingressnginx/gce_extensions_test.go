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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	providerir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func TestProcessSessionAffinity(t *testing.T) {
	testCases := []struct {
		name           string
		ingress        networkingv1.Ingress
		expectedSvcIRs map[types.NamespacedName]providerir.ProviderSpecificServiceIR
	}{
		{
			name: "no affinity annotation",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc1",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSvcIRs: map[types.NamespacedName]providerir.ProviderSpecificServiceIR{},
		},
		{
			name: "affinity cookie",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						AffinityAnnotation: "cookie",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc1",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSvcIRs: map[types.NamespacedName]providerir.ProviderSpecificServiceIR{
				{Namespace: "default", Name: "svc1"}: {
					Gce: &gce.ServiceIR{
						SessionAffinity: &gce.SessionAffinityConfig{
							AffinityType: "GENERATED_COOKIE",
						},
					},
				},
			},
		},
		{
			name: "affinity cookie with ttl",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						AffinityAnnotation:             "cookie",
						SessionCookieExpiresAnnotation: "3600",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc1",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSvcIRs: map[types.NamespacedName]providerir.ProviderSpecificServiceIR{
				{Namespace: "default", Name: "svc1"}: {
					Gce: &gce.ServiceIR{
						SessionAffinity: &gce.SessionAffinityConfig{
							AffinityType: "GENERATED_COOKIE",
							CookieTTLSec: ptr.To(int64(3600)),
						},
					},
				},
			},
		},
		{
			name: "affinity mode persistent",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						AffinityAnnotation:     "cookie",
						AffinityModeAnnotation: "persistent",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc1",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSvcIRs: map[types.NamespacedName]providerir.ProviderSpecificServiceIR{
				{Namespace: "default", Name: "svc1"}: {
					Gce: &gce.ServiceIR{
						SessionAffinity: &gce.SessionAffinityConfig{
							AffinityType: "GENERATED_COOKIE",
						},
						LocalityLbPolicy: ptr.To("MAGLEV"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ir := &providerir.ProviderIR{
				Services: make(map[types.NamespacedName]providerir.ProviderSpecificServiceIR),
			}
			processSessionAffinity(tc.ingress, ir)

			if diff := cmp.Diff(tc.expectedSvcIRs, ir.Services); diff != "" {
				t.Errorf("processSessionAffinity() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
