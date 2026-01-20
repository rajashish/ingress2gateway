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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
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

func TestProcessSecurityPolicy(t *testing.T) {
	testCases := []struct {
		name           string
		ingress        networkingv1.Ingress
		expectedSvcIRs map[types.NamespacedName]providerir.ProviderSpecificServiceIR
	}{
		{
			name: "whitelist source range",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						WhitelistSourceRangeAnnotation: "10.0.0.0/24",
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
						SecurityPolicy: &gce.SecurityPolicyConfig{
							Name: "whitelist-svc1",
						},
					},
				},
			},
		},
		{
			name: "limit rps",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						LimitRPSAnnotation: "10",
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
						SecurityPolicy: &gce.SecurityPolicyConfig{
							Name: "manual-cloud-armor-policy-required-ratelimit",
						},
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
			processSecurityPolicy(tc.ingress, ir)

			if diff := cmp.Diff(tc.expectedSvcIRs, ir.Services); diff != "" {
				t.Errorf("processSecurityPolicy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProcessIAP(t *testing.T) {
	testCases := []struct {
		name           string
		ingress        networkingv1.Ingress
		expectedSvcIRs map[types.NamespacedName]providerir.ProviderSpecificServiceIR
	}{
		{
			name: "auth secret",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						AuthSecretAnnotation: "my-secret",
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
						IAP: &gce.IAPConfig{
							Enabled: true,
							OAuth2ClientSecret: &gce.OAuth2ClientSecret{
									Name: "my-secret",
							},
						},
					},
				},
			},
		},
		{
			name: "enable global auth",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						EnableGlobalAuthAnnotation: "true",
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
						IAP: &gce.IAPConfig{
							Enabled: true,
						},
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
			processIAP(tc.ingress, ir)

			if diff := cmp.Diff(tc.expectedSvcIRs, ir.Services); diff != "" {
				t.Errorf("processIAP() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProcessTimeouts(t *testing.T) {
	testCases := []struct {
		name             string
		ingress          networkingv1.Ingress
		expectedTimeouts map[types.NamespacedName]*gatewayv1.HTTPRouteTimeouts
	}{
		{
			name: "read timeout",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						ProxyReadTimeoutAnnotation: "120",
					},
				},
			},
			expectedTimeouts: map[types.NamespacedName]*gatewayv1.HTTPRouteTimeouts{
				{Namespace: "default", Name: "route1"}: {
					BackendRequest: ptrToDuration("2m0s"),
				},
			},
		},
		{
			name: "send timeout",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						ProxySendTimeoutAnnotation: "60s",
					},
				},
			},
			expectedTimeouts: map[types.NamespacedName]*gatewayv1.HTTPRouteTimeouts{
				{Namespace: "default", Name: "route1"}: {
					BackendRequest: ptrToDuration("1m0s"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock IR with a route derived from this ingress
			ir := &providerir.ProviderIR{
				HTTPRoutes: map[types.NamespacedName]providerir.HTTPRouteContext{
					{Namespace: "default", Name: "route1"}: {
						HTTPRoute: gatewayv1.HTTPRoute{
							Spec: gatewayv1.HTTPRouteSpec{
								Rules: []gatewayv1.HTTPRouteRule{{}},
							},
						},
						RuleBackendSources: [][]providerir.BackendSource{
							{
								{Ingress: &tc.ingress},
							},
						},
					},
				},
			}

			processTimeouts(tc.ingress, ir)

			route := ir.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "route1"}]
			got := route.HTTPRoute.Spec.Rules[0].Timeouts
			want := tc.expectedTimeouts[types.NamespacedName{Namespace: "default", Name: "route1"}]

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("processTimeouts() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProcessBackendProtocol(t *testing.T) {
	testCases := []struct {
		name           string
		ingress        networkingv1.Ingress
		expectedSvcIRs map[types.NamespacedName]providerir.ProviderSpecificServiceIR
	}{
		{
			name: "backend protocol HTTPS",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						BackendProtocolAnnotation: "HTTPS",
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
						HealthCheck: &gce.HealthCheckConfig{
							Type: ptr.To("HTTPS"),
						},
					},
				},
			},
		},
		{
			name: "backend protocol GRPC",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test",
					Annotations: map[string]string{
						BackendProtocolAnnotation: "GRPC",
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
						HealthCheck: &gce.HealthCheckConfig{
							Type: ptr.To("HTTP2"),
						},
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
			processBackendProtocol(tc.ingress, ir)

			if diff := cmp.Diff(tc.expectedSvcIRs, ir.Services); diff != "" {
				t.Errorf("processBackendProtocol() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func ptrToDuration(s string) *gatewayv1.Duration {
	d := gatewayv1.Duration(s)
	return &d
}
