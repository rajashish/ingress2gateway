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
	"strings"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGceFeature_Redirects(t *testing.T) {
	ingressClass := "nginx"
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redirect-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/from-to-www-redirect": "true",
				"nginx.ingress.kubernetes.io/ssl-redirect":         "true",
				"nginx.ingress.kubernetes.io/permanent-redirect":   "/new-path",
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
	foundPermanentRedirect := false

	for _, filter := range routeIR.Spec.Rules[0].Filters {
		if filter.Type == gatewayv1.HTTPRouteFilterRequestRedirect {
			// Check for WWW redirect
			if filter.RequestRedirect.Hostname != nil && *filter.RequestRedirect.Hostname == "www.example.com" {
				foundWWWRedirect = true
				if filter.RequestRedirect.StatusCode == nil || *filter.RequestRedirect.StatusCode != 301 {
					t.Errorf("WWW Redirect status code mismatch: got %v", filter.RequestRedirect.StatusCode)
				}
			}
			// Check for Permanent Redirect (Path)
			if filter.RequestRedirect.Path != nil && filter.RequestRedirect.Path.ReplaceFullPath != nil && *filter.RequestRedirect.Path.ReplaceFullPath == "/new-path" {
				foundPermanentRedirect = true
				if filter.RequestRedirect.StatusCode == nil || *filter.RequestRedirect.StatusCode != 301 {
					t.Errorf("Permanent Redirect status code mismatch: got %v", filter.RequestRedirect.StatusCode)
				}
			}
		}
	}
	if !foundWWWRedirect {
		t.Error("from-to-www-redirect filter not found")
	}
	if !foundPermanentRedirect {
		t.Error("permanent-redirect filter not found")
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

func TestGceFeature_Timeouts_Filters_BackendProtocol(t *testing.T) {
	ingressClass := "nginx"
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "timeout-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
				"nginx.ingress.kubernetes.io/proxy-send-timeout": "30",
				"nginx.ingress.kubernetes.io/backend-protocol":   "HTTPS",
				"nginx.ingress.kubernetes.io/rewrite-target":     "/new",
				"nginx.ingress.kubernetes.io/upstream-vhost":     "backend.example.com",
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
											Name: "timeout-service",
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
			{Namespace: "default", Name: "timeout-service"}: {},
		},
		Gateways: map[types.NamespacedName]intermediate.GatewayContext{
			{Namespace: "default", Name: "nginx"}: {Gateway: gatewayv1.Gateway{}},
		},
		HTTPRoutes: map[types.NamespacedName]intermediate.HTTPRouteContext{
			{Namespace: "default", Name: "timeout-route"}: {
				HTTPRoute: gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "timeout-route",
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "timeout-service",
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]intermediate.BackendSource{
					{{Ingress: &ingress}},
				},
			},
		},
	}

	errs := gceFeature([]networkingv1.Ingress{ingress}, nil, &ir)
	if len(errs) > 0 {
		t.Fatalf("gceFeature returned errors: %v", errs)
	}

	// Verify Service IR (Backend Protocol)
	svcIR := ir.Services[types.NamespacedName{Namespace: "default", Name: "timeout-service"}]
	if svcIR.Gce == nil || svcIR.Gce.HealthCheck == nil || svcIR.Gce.HealthCheck.Type == nil || *svcIR.Gce.HealthCheck.Type != "HTTPS" {
		t.Error("Backend Protocol not set to HTTPS on Service IR")
	}

	// Verify HTTPRoute (Timeouts & Filters)
	routeIR := ir.HTTPRoutes[types.NamespacedName{Namespace: "default", Name: "timeout-route"}]
	rule := routeIR.Spec.Rules[0]

	// Timeouts
	if rule.Timeouts == nil || rule.Timeouts.Request == nil {
		t.Error("Request timeout is nil")
	} else if *rule.Timeouts.Request != gatewayv1.Duration("1m0s") {
		t.Errorf("Request timeout mismatch: got %v", *rule.Timeouts.Request)
	}
	if rule.Timeouts.BackendRequest == nil {
		t.Error("BackendRequest timeout is nil")
	} else if *rule.Timeouts.BackendRequest != gatewayv1.Duration("30s") {
		t.Errorf("BackendRequest timeout mismatch: got %v", *rule.Timeouts.BackendRequest)
	}

	// Filters
	foundRewrite := false
	foundVHost := false
	for _, filter := range rule.Filters {
		if filter.Type == gatewayv1.HTTPRouteFilterURLRewrite {
			foundRewrite = true
			if filter.URLRewrite.Path.ReplaceFullPath == nil || *filter.URLRewrite.Path.ReplaceFullPath != "/new" {
				t.Errorf("Rewrite target mismatch: got %v", filter.URLRewrite.Path.ReplaceFullPath)
			}
		}
		if filter.Type == gatewayv1.HTTPRouteFilterRequestHeaderModifier {
			for _, h := range filter.RequestHeaderModifier.Set {
				if h.Name == "Host" && h.Value == "backend.example.com" {
					foundVHost = true
				}
			}
		}
	}
	if !foundRewrite {
		t.Error("Rewrite filter not found")
	}
	if !foundVHost {
		t.Error("Upstream VHost filter not found")
	}
}

func TestGceFeature_Policies(t *testing.T) {
	ingressClass := "nginx"
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/whitelist-source-range": "10.0.0.0/24",
				"nginx.ingress.kubernetes.io/auth-secret":            "my-iap-secret",
				"nginx.ingress.kubernetes.io/affinity":               "cookie",
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
									Path: "/",
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "policy-service",
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
			{Namespace: "default", Name: "policy-service"}: {},
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
			{Namespace: "default", Name: "policy-route"}: {
				HTTPRoute: gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "policy-route",
						Namespace: "default",
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "policy-service",
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]intermediate.BackendSource{
					{{Ingress: &ingress}},
				},
			},
		},
	}

	errs := gceFeature([]networkingv1.Ingress{ingress}, nil, &ir)
	if len(errs) > 0 {
		t.Fatalf("gceFeature returned errors: %v", errs)
	}

	// Verify Service IR (Cloud Armor, IAP, Affinity)
	svcIR := ir.Services[types.NamespacedName{Namespace: "default", Name: "policy-service"}]
	if svcIR.Gce == nil {
		t.Fatal("Service IR Gce is nil")
	}
	
	// Cloud Armor
	if svcIR.Gce.SecurityPolicy == nil || !strings.Contains(svcIR.Gce.SecurityPolicy.Name, "whitelist-policy-service") {
		t.Errorf("SecurityPolicy missing or name mismatch: got %v", svcIR.Gce.SecurityPolicy)
	}

	// IAP
	if svcIR.Gce.Iap == nil || !svcIR.Gce.Iap.Enabled || svcIR.Gce.Iap.SecretName != "my-iap-secret" {
		t.Errorf("IAP config mismatch: %+v", svcIR.Gce.Iap)
	}

	// Affinity
	if svcIR.Gce.SessionAffinity == nil || svcIR.Gce.SessionAffinity.AffinityType != "GENERATED_COOKIE" {
		t.Errorf("SessionAffinity config mismatch: %+v", svcIR.Gce.SessionAffinity)
	}

	// Verify Gateway IR (SSL Policy)
	gwIR := ir.Gateways[types.NamespacedName{Namespace: "default", Name: "nginx"}]
	if gwIR.ProviderSpecificIR.Gce == nil || gwIR.ProviderSpecificIR.Gce.SslPolicy == nil || gwIR.ProviderSpecificIR.Gce.SslPolicy.Name != "manual-ssl-policy-required" {
		t.Errorf("Gateway SSL Policy mismatch: got %v", gwIR.ProviderSpecificIR.Gce)
	}
}
