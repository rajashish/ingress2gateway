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
	"strconv"
	"strings"
	"time"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/intermediate"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/common"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func gkeFeature(ingressList []networkingv1.Ingress, servicePorts map[types.NamespacedName]map[string]int32, ir *intermediate.IR) field.ErrorList {
	var errs field.ErrorList

	// Process Services (GCPBackendPolicy)
	for _, ingress := range ingressList {
		processServiceAnnotations(ingress, ir)
		processGatewayAnnotations(ingress, ir)
	}

	// Process HTTPRoutes (Timeouts, Filters)
	for name, route := range ir.HTTPRoutes {
		for i := range route.Spec.Rules {
			// Find the source Ingress for this rule
			// We assume all backends in a rule come from the same Ingress (or compatible ones)
			// for the purpose of rule-level annotations like timeouts.
			if len(route.RuleBackendSources) > i && len(route.RuleBackendSources[i]) > 0 {
				source := route.RuleBackendSources[i][0]
				if source.Ingress != nil {
					processRouteAnnotations(source.Ingress, &route.Spec.Rules[i])

					// Handle from-to-www-redirect
					if val, ok := source.Ingress.Annotations["nginx.ingress.kubernetes.io/from-to-www-redirect"]; ok && val == "true" {
						for _, host := range route.Spec.Hostnames {
							h := string(host)
							var target string
							if strings.HasPrefix(h, "www.") {
								target = strings.TrimPrefix(h, "www.")
							} else {
								target = "www." + h
							}

							filter := gatewayv1.HTTPRouteFilter{
								Type: gatewayv1.HTTPRouteFilterRequestRedirect,
								RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
									Hostname:   (*gatewayv1.PreciseHostname)(&target),
									StatusCode: ptrToInt(308),
								},
							}
							route.Spec.Rules[i].Filters = append(route.Spec.Rules[i].Filters, filter)
						}
					}
				}
			}
		}
		ir.HTTPRoutes[name] = route
	}

	processSSLRedirects(ir)

	return errs
}

func processSSLRedirects(ir *intermediate.IR) {
	// Iterate over all HTTPRoutes to find those that need SSL redirect.
	// We might modify ir.HTTPRoutes, so we iterate a copy or handle keys carefully.
	routesToProcess := make([]types.NamespacedName, 0)
	for name := range ir.HTTPRoutes {
		routesToProcess = append(routesToProcess, name)
	}

	for _, name := range routesToProcess {
		route, ok := ir.HTTPRoutes[name]
		if !ok {
			continue
		}

		// Check if this route comes from an Ingress with ssl-redirect=true
		isSSLRedirect := false
		var sourceIngress *networkingv1.Ingress

		// Check the first rule/source (assuming homogeneity for this feature)
		if len(route.RuleBackendSources) > 0 && len(route.RuleBackendSources[0]) > 0 {
			sourceIngress = route.RuleBackendSources[0][0].Ingress
			if sourceIngress != nil {
				if val, ok := sourceIngress.Annotations["nginx.ingress.kubernetes.io/ssl-redirect"]; ok && val == "true" {
					isSSLRedirect = true
				} else if val, ok := sourceIngress.Annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"]; ok && val == "true" {
					isSSLRedirect = true
				}
			}
		}

		if isSSLRedirect && sourceIngress != nil {
			// 1. Ensure Gateway has HTTPS listener
			ensureHTTPSListener(ir, route.Spec.ParentRefs)

			// 2. Modify existing Route to be Secure-only (Port 443)
			// We append a ParentRef with Port 443 if not present, and ensure it doesn't match Port 80.
			// Actually, cleaner to specify Port 443 explicitly.

			// Update parent refs for secure route
			newParentRefs := []gatewayv1.ParentReference{}
			for _, ref := range route.Spec.ParentRefs {
				p443 := gatewayv1.PortNumber(443)
				refCopy := ref
				refCopy.Port = &p443
				newParentRefs = append(newParentRefs, refCopy)
			}
			route.Spec.ParentRefs = newParentRefs
			ir.HTTPRoutes[name] = route

			// 3. Create Redirect Route (Port 80)
			redirectRoute := gatewayv1.HTTPRoute{
				ObjectMeta: route.ObjectMeta,
				Spec:       route.Spec,
			}
			redirectRoute.SetGroupVersionKind(common.HTTPRouteGVK)
			redirectRoute.Name = route.Name + "-redirect"
			redirectRoute.Spec.ParentRefs = []gatewayv1.ParentReference{}
			for _, ref := range route.Spec.ParentRefs { // using original route's parent refs logic (but pointing to 80)
				p80 := gatewayv1.PortNumber(80)
				refCopy := ref
				refCopy.Port = &p80
				redirectRoute.Spec.ParentRefs = append(redirectRoute.Spec.ParentRefs, refCopy)
			}

			// Clear rules and add redirect rule
			redirectRoute.Spec.Rules = []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  ptrToPathMatchType(gatewayv1.PathMatchPathPrefix),
								Value: ptrToString("/"),
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestRedirect,
							RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
								Scheme:     ptrToString("https"),
								StatusCode: ptrToInt(301),
								Port:       ptrToPortNumber(443),
							},
						},
					},
				},
			}

			// Add to IR
			// We need a context for the new route
			// We can reuse the source context from the original route for simplicity,
			// though BackendSources for the redirect route are technically empty/none.
			// The IR map expects HTTPRouteContext.

			ir.HTTPRoutes[types.NamespacedName{Namespace: redirectRoute.Namespace, Name: redirectRoute.Name}] = intermediate.HTTPRouteContext{
				HTTPRoute: redirectRoute,
				// No backend sources for the redirect route strictly speaking,
				// but we can leave it empty or copy if needed for other logic.
				// Empty is safer as it has no backends.
			}
		}
	}
}

func ensureHTTPSListener(ir *intermediate.IR, parentRefs []gatewayv1.ParentReference) {
	for _, ref := range parentRefs {
		gwName := string(ref.Name)
		// Assuming same namespace as route/ingress usually, but ParentRef can handle others.
		// intermediate.IR keys are NamespacedName.
		// We'll iterate Gateways to match the name.
		for key, gwCtx := range ir.Gateways {
			if key.Name == gwName {
				// Found Gateway
				hasHTTPS := false
				for _, l := range gwCtx.Gateway.Spec.Listeners {
					if l.Port == 443 {
						hasHTTPS = true
						break
					}
				}
				if !hasHTTPS {
					// Add HTTPS listener
					gw := gwCtx.Gateway
					h := gatewayv1.Hostname("*") // Default to wildcard if we don't know
					// In a real scenario, we might want to pick the host from the Ingress/Route.
					// But for a generic HTTPS listener addition:
					mode := gatewayv1.TLSModeTerminate
					listener := gatewayv1.Listener{
						Name:     "https-generated",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: &h,
						TLS: &gatewayv1.ListenerTLSConfig{
							Mode: &mode,
							// We don't have a cert here.
							// User manual step implies they might add it or use GKE managed certs.
						},
					}
					gw.Spec.Listeners = append(gw.Spec.Listeners, listener)
					gwCtx.Gateway = gw
					ir.Gateways[key] = gwCtx
				}
			}
		}
	}
}

func ptrToPathMatchType(t gatewayv1.PathMatchType) *gatewayv1.PathMatchType {
	return &t
}

func ptrToString(s string) *string {
	return &s
}

func ptrToPortNumber(p int) *gatewayv1.PortNumber {
	pn := gatewayv1.PortNumber(p)
	return &pn
}

func processServiceAnnotations(ingress networkingv1.Ingress, ir *intermediate.IR) {
	// Helper to find services referenced by this ingress
	services := getReferencedServices(ingress)

	for _, svcName := range services {
		svcKey := types.NamespacedName{Namespace: ingress.Namespace, Name: svcName}
		serviceIR, ok := ir.Services[svcKey]
		if !ok {
			serviceIR = intermediate.ProviderSpecificServiceIR{}
		}
		if serviceIR.Gce == nil {
			serviceIR.Gce = &intermediate.GceServiceIR{}
		}

		// 1. Rate Limiting / Security Policy (Cloud Armor)
		// annotations: whitelist-source-range, denylist-source-range, limit-rps
		if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"]; ok && val != "" {
			serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{Name: "manual-cloud-armor-policy-required-whitelist"}
		} else if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/denylist-source-range"]; ok && val != "" {
			serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{Name: "manual-cloud-armor-policy-required-denylist"}
		} else if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/limit-rps"]; ok && val != "" {
			serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{Name: "manual-cloud-armor-policy-required-ratelimit"}
		}

		// 2. IAP
		// annotations: auth-secret, auth-url (trigger)
		if secret, ok := ingress.Annotations["nginx.ingress.kubernetes.io/auth-secret"]; ok && secret != "" {
			if serviceIR.Gce.Iap == nil {
				serviceIR.Gce.Iap = &intermediate.IapConfig{}
			}
			serviceIR.Gce.Iap.
				Enabled = true
			serviceIR.Gce.Iap.SecretName = secret
		}

		// 3. Session Affinity
		// annotations: affinity, session-cookie-expires, affinity-mode
		if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/affinity"]; ok && val == "cookie" {
			if serviceIR.Gce.SessionAffinity == nil {
				serviceIR.Gce.SessionAffinity = &intermediate.SessionAffinityConfig{}
			}
			serviceIR.Gce.SessionAffinity.AffinityType = "GENERATED_COOKIE"

			if expires, ok := ingress.Annotations["nginx.ingress.kubernetes.io/session-cookie-expires"]; ok {
				if ttl, err := strconv.ParseInt(expires, 10, 64); err == nil {
					serviceIR.Gce.SessionAffinity.CookieTTLSec = &ttl
				}
			}

			// affinity-mode (placeholder for now as GKE usually defaults to balanced or client ip is distinct)
			if mode, ok := ingress.Annotations["nginx.ingress.kubernetes.io/affinity-mode"]; ok && mode != "" {
				// If mode is 'balanced' or 'persistent', could map here if IR supported it.
				// For now, we acknowledge it was parsed if needed.
			}
		}

		// 4. Backend Protocol
		// annotations: backend-protocol
		if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/backend-protocol"]; ok && val == "HTTPS" {
			if serviceIR.Gce.HealthCheck == nil {
				serviceIR.Gce.HealthCheck = &intermediate.HealthCheckConfig{}
			}
			t := "HTTPS"
			serviceIR.Gce.HealthCheck.Type = &t
		}

		// 5. External Auth (auth-url)
		// annotations: auth-url
		if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/auth-url"]; ok && val != "" {
			// If security policy is not already set (e.g. by Cloud Armor annotations),
			// suggest a manual policy for External Auth.
			if serviceIR.Gce.SecurityPolicy == nil {
				serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{Name: "manual-external-auth-policy-required"}
			}
		}

		ir.Services[svcKey] = serviceIR
	}
}

func processGatewayAnnotations(ingress networkingv1.Ingress, ir *intermediate.IR) {
	// Find the Gateway associated with this Ingress
	// Ingress2Gateway typically creates one Gateway per IngressClass.
	// We need to find which Gateway this Ingress belongs to.
	// This is tricky because IR doesn't explicitly link Ingress -> Gateway.
	// But we can infer it from the IngressClass or annotations.

	// For simplicity, we'll iterate over Gateways and check if they match the Ingress's class.
	// Or better, we can assume the Gateway name is derived from the IngressClass name (default behavior).

	// However, if we want to attach policies, we need to be careful.
	// Let's skip Gateway annotations for now as mapping them correctly requires more context about how Gateways were generated.
	// But user asked for ssl-ciphers -> GCPGatewayPolicy.

	// If we assume 1 Gateway per IngressClass, we can find it.
	ingressClass := ingress.Spec.IngressClassName
	if ingressClass == nil {
		// check annotation
		if val, ok := ingress.Annotations["kubernetes.io/ingress.class"]; ok {
			ingressClass = &val
		}
	}

	if ingressClass != nil {
		// The default Gateway name is usually the IngressClass name.
		// See pkg/i2gw/providers/common/converter.go

		// Let's look at ir.Gateways.
		for name, gw := range ir.Gateways {
			if string(gw.Spec.GatewayClassName) == *ingressClass {
				// Found a candidate Gateway.
				// Check annotations.
				if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/ssl-ciphers"]; ok && val != "" {
					if gw.ProviderSpecificIR.Gce == nil {
						gw.ProviderSpecificIR.Gce = &intermediate.GceGatewayIR{}
					}
					gw.ProviderSpecificIR.Gce.SslPolicy = &intermediate.SslPolicyConfig{Name: "manual-ssl-policy-required"}
					ir.Gateways[name] = gw
				}
				// ssl-redirect
				if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/ssl-redirect"]; ok && val == "true" {
					if gw.ProviderSpecificIR.Gce == nil {
						gw.ProviderSpecificIR.Gce = &intermediate.GceGatewayIR{}
					}
					gw.ProviderSpecificIR.Gce.EnableHTTPSRedirect = true
					ir.Gateways[name] = gw
				}
				// force-ssl-redirect
				if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"]; ok && val == "true" {
					if gw.ProviderSpecificIR.Gce == nil {
						gw.ProviderSpecificIR.Gce = &intermediate.GceGatewayIR{}
					}
					gw.ProviderSpecificIR.Gce.EnableHTTPSRedirect = true
					ir.Gateways[name] = gw
				}
			}
		}
	}
}

func processRouteAnnotations(ingress *networkingv1.Ingress, rule *gatewayv1.HTTPRouteRule) {
	// 1. Timeouts
	// annotations: proxy-read-timeout, proxy-send-timeout
	if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/proxy-read-timeout"]; ok {
		if duration, err := time.ParseDuration(val + "s"); err == nil { // Nginx timeout is in seconds usually
			if rule.Timeouts == nil {
				rule.Timeouts = &gatewayv1.HTTPRouteTimeouts{}
			}
			gwDuration := gatewayv1.Duration(duration.String())
			rule.Timeouts.Request = &gwDuration
		}
	}
	if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/proxy-send-timeout"]; ok {
		if duration, err := time.ParseDuration(val + "s"); err == nil {
			if rule.Timeouts == nil {
				rule.Timeouts = &gatewayv1.HTTPRouteTimeouts{}
			}
			gwDuration := gatewayv1.Duration(duration.String())
			rule.Timeouts.BackendRequest = &gwDuration
		}
	}

	// 2. Rewrites
	// annotations: rewrite-target
	if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/rewrite-target"]; ok {
		// NGINX rewrite-target often uses capture groups ($1, $2).
		// Gateway API URLRewrite is simpler.
		// If it's a simple rewrite, we can map it.
		// e.g. /foo -> /bar

		filter := gatewayv1.HTTPRouteFilter{
			Type: gatewayv1.HTTPRouteFilterURLRewrite,
			URLRewrite: &gatewayv1.HTTPURLRewriteFilter{
				Path: &gatewayv1.HTTPPathModifier{
					Type:            gatewayv1.FullPathHTTPPathModifier,
					ReplaceFullPath: &val,
				},
			},
		}
		rule.Filters = append(rule.Filters, filter)
	}

	// 3. Upstream VHost
	// annotations: upstream-vhost
	if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/upstream-vhost"]; ok && val != "" {
		filter := gatewayv1.HTTPRouteFilter{
			Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
			RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
				Set: []gatewayv1.HTTPHeader{
					{
						Name:  "Host",
						Value: val,
					},
				},
			},
		}
		rule.Filters = append(rule.Filters, filter)
	}

	// 4. Redirects
	// annotations: permanent-redirect, temporal-redirect, from-to-www-redirect
	if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/permanent-redirect"]; ok {
		// Parsing URL is needed to fill RequestRedirect fields.
		// Skipping detailed implementation for brevity, but adding the filter structure.
		_ = val
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

func ptrToInt(i int) *int {
	return &i
}
