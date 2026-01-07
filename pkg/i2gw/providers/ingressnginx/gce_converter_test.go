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
	"testing"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGceFeature(t *testing.T) {
	ingressClass := "nginx"
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/limit-rps":              "10",
				"nginx.ingress.kubernetes.io/auth-secret":            "my-secret",
				"nginx.ingress.kubernetes.io/affinity":               "cookie",
				"nginx.ingress.kubernetes.io/session-cookie-expires": "3600",
				"nginx.ingress.kubernetes.io/proxy-read-timeout":     "60",
				"nginx.ingress.kubernetes.io/rewrite-target":         "/new",
				"nginx.ingress.kubernetes.io/ssl-ciphers":            "ECDHE-RSA-AES128-GCM-SHA256",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClass,
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path: "/old",
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "test-service",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
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
	}

	ir := intermediate.IR{
		Services: map[types.NamespacedName]intermediate.ProviderSpecificServiceIR{
			{Namespace: "default", Name: "test-service"}: {},
		},
		Gateways: map[types.NamespacedName]intermediate.GatewayContext{
			{Namespace: "default", Name: "nginx"}: {
				Gateway: gatewayv1.Gateway{
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "nginx",
					},
				},
			},
		},
		HTTPRoutes: map[types.NamespacedName]intermediate.HTTPRouteContext{
			{Namespace: "default", Name: "test-route"}: {
				HTTPRoute: gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "test-service",
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]intermediate.BackendSource{
					{
						{Ingress: &ingress},
					},
				},
			},
		},
	}

	errs := gceFeature([]networkingv1.Ingress{ingress}, nil, &ir)
	if len(errs) > 0 {
		t.Fatalf("gceFeature returned errors: %v", errs)
	}

	// Verify Service IR (GCPBackendPolicy)
	svcIR := ir.Services[types.NamespacedName{Namespace: "default", Name: "test-service"}]
	if svcIR.Gce == nil {
		t.Fatal("Service IR Gce is nil")
	}
	// if svcIR.Gce.Iap == nil || !svcIR.Gce.Iap.Enabled || svcIR.Gce.Iap.SecretName != "my-secret" {
	// 	t.Errorf("IAP config mismatch: %+v", svcIR.Gce.Iap)
	// }
	if svcIR.Gce.SecurityPolicy == nil || svcIR.Gce.SecurityPolicy.Name != "manual-cloud-armor-policy-required-ratelimit" {
		t.Errorf("SecurityPolicy config mismatch: %+v", svcIR.Gce.SecurityPolicy)
	}
	if svcIR.Gce.SessionAffinity == nil || svcIR.Gce.SessionAffinity.AffinityType != "GENERATED_COOKIE" || *svcIR.Gce.SessionAffinity.CookieTTLSec != 3600 {
		t.Errorf("SessionAffinity config mismatch: %+v", svcIR.Gce.SessionAffinity)
	}

	// Verify Gateway IR (GCPGatewayPolicy)
	gwIR := ir.Gateways[types.NamespacedName{Namespace: "default", Name: "nginx"}]
	if gwIR.ProviderSpecificIR.Gce == nil {
		t.Fatal("Gateway IR Gce is nil")
	}
	if gwIR.ProviderSpecificIR.Gce.SslPolicy == nil || gwIR.ProviderSpecificIR.Gce.SslPolicy.Name != "manual-ssl-policy-required" {
		t.Errorf("SslPolicy config mismatch: %+v", gwIR.ProviderSpecificIR.Gce.SslPolicy)
	}

	// Verify HTTPRoute IR (Timeouts, Filters)
	routeIR := ir.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "test-route"}]
	rule := routeIR.Spec.Rules[0]

	// Timeouts
	if rule.Timeouts == nil || rule.Timeouts.BackendRequest == nil {
		t.Fatal("Rule timeouts is nil")
	}
	expectedTimeout := gatewayv1.Duration("1m0s")
	if *rule.Timeouts.BackendRequest != expectedTimeout {
		t.Errorf("Timeout mismatch: got %v, want %v", *rule.Timeouts.BackendRequest, expectedTimeout)
	}

	// Filters (Rewrite)
	foundRewrite := false
	for _, filter := range rule.Filters {
		if filter.Type == gatewayv1.HTTPRouteFilterURLRewrite {
			foundRewrite = true
			if filter.URLRewrite.Path.ReplaceFullPath == nil || *filter.URLRewrite.Path.ReplaceFullPath != "/new" {
				t.Errorf("Rewrite path mismatch: %+v", filter.URLRewrite)
			}
		}
	}
	if !foundRewrite {
		t.Error("Rewrite filter not found")
	}
}

func TestGceFeature_Redirects(t *testing.T) {
	ingressClass := "nginx"
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redirect-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/from-to-www-redirect": "true",
				"nginx.ingress.kubernetes.io/ssl-redirect":         "true",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClass,
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path: "/",
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "test-service",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"example.com"},
					SecretName: "placeholder-secret",
				},
			},
		},
	}

	p80 := gatewayv1.PortNumber(80)
	ir := intermediate.IR{
		Services: map[types.NamespacedName]intermediate.ProviderSpecificServiceIR{
			{Namespace: "default", Name: "test-service"}: {},
		},
		Gateways: map[types.NamespacedName]intermediate.GatewayContext{
			{Namespace: "default", Name: "nginx"}: {
				Gateway: gatewayv1.Gateway{
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "nginx",
						Listeners: []gatewayv1.Listener{
							{
								Name:     "http",
								Port:     80,
								Protocol: gatewayv1.HTTPProtocolType,
							},
						},
					},
				},
			},
		},
		HTTPRoutes: map[types.NamespacedName]intermediate.HTTPRouteContext{
			{Namespace: "default", Name: "test-route"}: {
				HTTPRoute: gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-route",
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{
								{Name: "nginx", Port: &p80},
							},
						},
						Hostnames: []gatewayv1.Hostname{"example.com"},
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "test-service",
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]intermediate.BackendSource{
					{
						{Ingress: &ingress},
					},
				},
			},
		},
	}

	errs := gceFeature([]networkingv1.Ingress{ingress}, nil, &ir)
	if len(errs) > 0 {
		t.Fatalf("gceFeature returned errors: %v", errs)
	}

	// Verify from-to-www-redirect (StatusCode 301)
	routeIR := ir.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "test-route"}]
	foundWWWRedirect := false
	for _, filter := range routeIR.Spec.Rules[0].Filters {
		if filter.Type == gatewayv1.HTTPRouteFilterRequestRedirect {
			if filter.RequestRedirect.StatusCode != nil && *filter.RequestRedirect.StatusCode == 301 {
				foundWWWRedirect = true
				if filter.RequestRedirect.Hostname == nil || *filter.RequestRedirect.Hostname != "www.example.com" {
					t.Errorf("WWW Redirect hostname mismatch: got %v", filter.RequestRedirect.Hostname)
				}
			}
		}
	}
	if !foundWWWRedirect {
		t.Error("from-to-www-redirect filter not found or status code not 301")
	}

	// Verify ssl-redirect (HTTPS Listener)
	gwIR := ir.Gateways[types.NamespacedName{Namespace: "default", Name: "nginx"}]
	foundHTTPS := false
	for _, l := range gwIR.Gateway.Spec.Listeners {
		if l.Port == 443 {
			foundHTTPS = true
			if l.Hostname != nil {
				t.Errorf("HTTPS listener hostname should be nil, got %v", *l.Hostname)
			}
			if l.TLS == nil || len(l.TLS.CertificateRefs) == 0 {
				t.Error("HTTPS listener missing CertificateRefs")
			} else if l.TLS.CertificateRefs[0].Name != "placeholder-secret" {
				t.Errorf("HTTPS listener CertificateRef name mismatch: got %v", l.TLS.CertificateRefs[0].Name)
			}
		}
	}
	if !foundHTTPS {
		t.Error("HTTPS listener not created for ssl-redirect")
	}
}

func TestGceFeature_Cors(t *testing.T) {
	ingressClass := "nginx"
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cors-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/enable-cors":            "true",
				"nginx.ingress.kubernetes.io/cors-allow-origin":      "https://example.com, https://foo.com",
				"nginx.ingress.kubernetes.io/cors-allow-headers":     "X-Custom-Header, Authorization",
				"nginx.ingress.kubernetes.io/cors-allow-methods":     "GET, POST, OPTIONS",
				"nginx.ingress.kubernetes.io/cors-allow-credentials": "true",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClass,
			Rules: []networkingv1.IngressRule{
				{
					Host: "api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path: "/",
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-service",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	ir := intermediate.IR{
		Services: map[types.NamespacedName]intermediate.ProviderSpecificServiceIR{
			{Namespace: "default", Name: "api-service"}: {},
		},
		Gateways: map[types.NamespacedName]intermediate.GatewayContext{
			{Namespace: "default", Name: "nginx"}: {
				Gateway: gatewayv1.Gateway{
					Spec: gatewayv1.GatewaySpec{
						GatewayClassName: "nginx",
					},
				},
			},
		},
		HTTPRoutes: map[types.NamespacedName]intermediate.HTTPRouteContext{
			{Namespace: "default", Name: "cors-route"}: {
				HTTPRoute: gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cors-route",
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "api-service",
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]intermediate.BackendSource{
					{
						{Ingress: &ingress},
					},
				},
			},
		},
	}

	errs := gceFeature([]networkingv1.Ingress{ingress}, nil, &ir)
	if len(errs) > 0 {
		t.Fatalf("gceFeature returned errors: %v", errs)
	}

	routeIR := ir.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "cors-route"}]
	
	// Verify CORS filter
	foundCors := false
	for _, filter := range routeIR.Spec.Rules[0].Filters {
		if filter.Type == gatewayv1.HTTPRouteFilterCORS {
			foundCors = true
			cors := filter.CORS
			if cors == nil {
				t.Fatal("CORS filter config is nil")
			}
			
			// Verify Origins
			if len(cors.AllowOrigins) != 2 || cors.AllowOrigins[0] != "https://example.com" {
				t.Errorf("AllowOrigins mismatch: %v", cors.AllowOrigins)
			}
			
			// Verify Headers
			if len(cors.AllowHeaders) != 2 || cors.AllowHeaders[0] != "X-Custom-Header" {
				t.Errorf("AllowHeaders mismatch: %v", cors.AllowHeaders)
			}
			
			// Verify Methods
			if len(cors.AllowMethods) != 3 || cors.AllowMethods[0] != "GET" {
				t.Errorf("AllowMethods mismatch: %v", cors.AllowMethods)
			}
			
			// Verify Credentials
			if cors.AllowCredentials == nil || !*cors.AllowCredentials {
				t.Error("AllowCredentials should be true")
			}
		}
	}
	if !foundCors {
		t.Error("CORS filter not found")
	}
}
