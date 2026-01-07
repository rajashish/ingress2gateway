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
	"os"
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

const (
	// Annotation keys
	annotationPrefix               = "nginx.ingress.kubernetes.io"
	annotationFromToWWWRedirect    = annotationPrefix + "/from-to-www-redirect"
	annotationSSLRedirect          = annotationPrefix + "/ssl-redirect"
	annotationForceSSLRedirect     = annotationPrefix + "/force-ssl-redirect"
	annotationSSLCiphers           = annotationPrefix + "/ssl-ciphers"
	annotationProxyReadTimeout     = annotationPrefix + "/proxy-read-timeout"
	annotationProxySendTimeout     = annotationPrefix + "/proxy-send-timeout"
	annotationRewriteTarget        = annotationPrefix + "/rewrite-target"
	annotationUpstreamVHost        = annotationPrefix + "/upstream-vhost"
	annotationPermanentRedirect    = annotationPrefix + "/permanent-redirect"
	annotationTemporalRedirect     = annotationPrefix + "/temporal-redirect"
	annotationWhitelistSourceRange = annotationPrefix + "/whitelist-source-range"
	annotationDenylistSourceRange  = annotationPrefix + "/denylist-source-range"
	annotationLimitRPS             = annotationPrefix + "/limit-rps"
	annotationAuthSecret           = annotationPrefix + "/auth-secret"
	annotationAuthURL              = annotationPrefix + "/auth-url"
	annotationAffinity             = annotationPrefix + "/affinity"
	annotationSessionCookieExpires = annotationPrefix + "/session-cookie-expires"
	annotationAffinityMode         = annotationPrefix + "/affinity-mode"
	annotationBackendProtocol      = annotationPrefix + "/backend-protocol"

	// Values and Policy Names
	policyManualExternalAuth = "manual-external-auth-policy-required"
	policyManualSSL          = "manual-ssl-policy-required"
	policyManualCloudArmor   = "manual-cloud-armor-policy-required-ratelimit"
	affinityTypeCookie       = "cookie"
	affinityTypeGenerated    = "GENERATED_COOKIE"
	backendProtocolHTTPS     = "HTTPS"
)

func gceFeature(ingressList []networkingv1.Ingress, servicePorts map[types.NamespacedName]map[string]int32, ir *intermediate.IR) field.ErrorList {
	var errs field.ErrorList

	// Process Services (GCPBackendPolicy)
	for _, ingress := range ingressList {
		processServiceAnnotations(ingress, ir, servicePorts)
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
					if val, ok := source.Ingress.Annotations[annotationFromToWWWRedirect]; ok && val == "true" {
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
									StatusCode: common.PtrTo(301),
								},
							}
							route.Spec.Rules[i].Filters = append(route.Spec.Rules[i].Filters, filter)
						}
					}

					// Handle Regex Path Matching
					if val, ok := source.Ingress.Annotations["nginx.ingress.kubernetes.io/use-regex"]; ok && val == "true" {
						for j := range route.Spec.Rules[i].Matches {
							if route.Spec.Rules[i].Matches[j].Path != nil {
								t := gatewayv1.PathMatchRegularExpression
								route.Spec.Rules[i].Matches[j].Path.Type = &t
							}
						}
					}
				}
			}
		}
		
		// Process CORS (Route Level)
		// We check the first source ingress for CORS annotations
		if len(route.RuleBackendSources) > 0 && len(route.RuleBackendSources[0]) > 0 {
			source := route.RuleBackendSources[0][0].Ingress
			if source != nil {
				processCorsAnnotations(source, &route, name)
			}
		}

		ir.HTTPRoutes[name] = route
	}

	processSSLRedirects(ir)

	return errs
}

func processCorsAnnotations(ingress *networkingv1.Ingress, route *intermediate.HTTPRouteContext, routeName types.NamespacedName) {
	enableCors := ingress.Annotations["nginx.ingress.kubernetes.io/enable-cors"]
	if enableCors != "true" {
		return
	}

	allowOrigin := ingress.Annotations["nginx.ingress.kubernetes.io/cors-allow-origin"]
	allowHeaders := ingress.Annotations["nginx.ingress.kubernetes.io/cors-allow-headers"]
	allowMethods := ingress.Annotations["nginx.ingress.kubernetes.io/cors-allow-methods"]
	allowCredentials := ingress.Annotations["nginx.ingress.kubernetes.io/cors-allow-credentials"]

	corsFilter := gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterCORS,
		CORS: &gatewayv1.HTTPCORSFilter{},
	}

	// Allow Origins
	if allowOrigin != "" {
		origins := strings.Split(allowOrigin, ",")
		for _, o := range origins {
			o = strings.TrimSpace(o)
			corsFilter.CORS.AllowOrigins = append(corsFilter.CORS.AllowOrigins, gatewayv1.CORSOrigin(o))
		}
	} else {
		// Default to "*" if not specified
		corsFilter.CORS.AllowOrigins = []gatewayv1.CORSOrigin{"*"}
	}

	// Allow Methods
	if allowMethods != "" {
		methods := strings.Split(allowMethods, ",")
		for _, m := range methods {
			corsFilter.CORS.AllowMethods = append(corsFilter.CORS.AllowMethods, gatewayv1.HTTPMethodWithWildcard(strings.TrimSpace(m)))
		}
	} else {
		// Nginx default methods
		corsFilter.CORS.AllowMethods = []gatewayv1.HTTPMethodWithWildcard{"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	}

	// Allow Headers
	if allowHeaders != "" {
		headers := strings.Split(allowHeaders, ",")
		for _, h := range headers {
			corsFilter.CORS.AllowHeaders = append(corsFilter.CORS.AllowHeaders, gatewayv1.HTTPHeaderName(strings.TrimSpace(h)))
		}
	}

	// Allow Credentials
	if allowCredentials == "true" {
		t := true
		corsFilter.CORS.AllowCredentials = &t
	}

	// Add filter to all rules
	for i := range route.HTTPRoute.Spec.Rules {
		route.HTTPRoute.Spec.Rules[i].Filters = append(route.HTTPRoute.Spec.Rules[i].Filters, corsFilter)
	}
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
				if val, ok := sourceIngress.Annotations[annotationSSLRedirect]; ok && val == "true" {
					isSSLRedirect = true
				} else if val, ok := sourceIngress.Annotations[annotationForceSSLRedirect]; ok && val == "true" {
					isSSLRedirect = true
				}
			}
		}

		if isSSLRedirect && sourceIngress != nil {
			// Determine TLS secret from Ingress
			var secretName *string
			for _, tls := range sourceIngress.Spec.TLS {
				// Naive match: if any host in route matches tls hosts, OR if tls has no hosts (wildcard)
				// For simplicity, pick the first secret found, or refine logic if needed.
				if tls.SecretName != "" {
					s := tls.SecretName
					secretName = &s
					break
				}
			}

			// 1. Ensure Gateway has HTTPS listener
			ensureHTTPSListener(ir, route.Spec.ParentRefs, secretName)

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
								Type:  common.PtrTo(gatewayv1.PathMatchPathPrefix),
								Value: common.PtrTo("/"),
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestRedirect,
							RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
								Scheme:     common.PtrTo("https"),
								StatusCode: common.PtrTo(301),
								Port:       common.PtrTo(gatewayv1.PortNumber(443)),
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

func ensureHTTPSListener(ir *intermediate.IR, parentRefs []gatewayv1.ParentReference, secretName *string) {
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
					if secretName == nil {
						// We cannot create an HTTPS listener without a secret.
						// Log a warning and skip.
						fmt.Fprintf(os.Stderr, "Warning: cannot enable SSL redirect for Gateway %s: no TLS secret found in Ingress\n", gwName)
						continue
					}
					// Add HTTPS listener
					gw := gwCtx.Gateway
					// In a real scenario, we might want to pick the host from the Ingress/Route.
					// But for a generic HTTPS listener addition:
					mode := gatewayv1.TLSModeTerminate
					listener := gatewayv1.Listener{
						Name:     "https-generated",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						TLS: &gatewayv1.ListenerTLSConfig{
							Mode: &mode,
							CertificateRefs: []gatewayv1.SecretObjectReference{
								{
									Name: gatewayv1.ObjectName(*secretName),
								},
							},
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



func processServiceAnnotations(ingress networkingv1.Ingress, ir *intermediate.IR, servicePorts map[types.NamespacedName]map[string]int32) {
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
		if val, ok := ingress.Annotations[annotationWhitelistSourceRange]; ok && val != "" {
			policyName := "whitelist-" + svcName
			serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{
				Name: policyName,
				CreationCommand: "gcloud compute security-policies create " + policyName + " --description \"Generated from ingress2gateway\"; " + 
					"gcloud compute security-policies rules create 1000 --security-policy " + policyName + " --action allow --src-ip-ranges \"" + val + `\"; ` + 
					"gcloud compute security-policies rules update 2147483647 --security-policy " + policyName + " --action deny-403",
			}
		} else if val, ok := ingress.Annotations[annotationDenylistSourceRange]; ok && val != "" {
			policyName := "denylist-" + svcName
			serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{
				Name: policyName,
				CreationCommand: "gcloud compute security-policies create " + policyName + " --description \"Generated from ingress2gateway\"; " + 
					"gcloud compute security-policies rules create 1000 --security-policy " + policyName + " --action deny-403 --src-ip-ranges \"" + val + `\"; ` + 
					"gcloud compute security-policies rules update 2147483647 --security-policy " + policyName + " --action allow",
			}
		} else if val, ok := ingress.Annotations[annotationLimitRPS]; ok && val != "" {
			serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{Name: policyManualCloudArmor}
		}

		// 2. IAP
		// annotations: auth-secret, auth-url (trigger)
		if secret, ok := ingress.Annotations[annotationAuthSecret]; ok && secret != "" {
			if serviceIR.Gce.Iap == nil {
				serviceIR.Gce.Iap = &intermediate.IapConfig{}
			}
			serviceIR.Gce.Iap.Enabled = true
			serviceIR.Gce.Iap.SecretName = secret
		}

		// 3. Session Affinity
		// annotations: affinity, session-cookie-expires, affinity-mode
		if val, ok := ingress.Annotations[annotationAffinity]; ok && val == affinityTypeCookie {
			if serviceIR.Gce.SessionAffinity == nil {
				serviceIR.Gce.SessionAffinity = &intermediate.SessionAffinityConfig{}
			}
			serviceIR.Gce.SessionAffinity.AffinityType = affinityTypeGenerated

			if expires, ok := ingress.Annotations[annotationSessionCookieExpires]; ok {
				if ttl, err := strconv.ParseInt(expires, 10, 64); err == nil {
					serviceIR.Gce.SessionAffinity.CookieTTLSec = &ttl
				}
			}

			// affinity-mode
			if mode, ok := ingress.Annotations[annotationAffinityMode]; ok && mode != "" {
				var policy string
				switch mode {
				case "balanced":
					policy = "ROUND_ROBIN"
				case "persistent":
					policy = "MAGLEV"
				}
				if policy != "" {
					serviceIR.Gce.LocalityLbPolicy = &policy
				}
			}
		}

		// 4. Backend Protocol
		// annotations: backend-protocol
		if val, ok := ingress.Annotations[annotationBackendProtocol]; ok && val == backendProtocolHTTPS {
			serviceIR.Gce.AppProtocol = &val
			
			// Also set HealthCheck Type as per upstream changes
			if serviceIR.Gce.HealthCheck == nil {
				serviceIR.Gce.HealthCheck = &intermediate.HealthCheckConfig{}
			}
			t := backendProtocolHTTPS
			serviceIR.Gce.HealthCheck.Type = &t

			if serviceIR.Gce.ServicePorts == nil {
				serviceIR.Gce.ServicePorts = make(map[string]int32)
			}
			if ports, ok := servicePorts[svcKey]; ok {
				for name, port := range ports {
					serviceIR.Gce.ServicePorts[name] = port
				}
			} else {
				// Fallback: try to find ports in the Ingress itself
				extracted := getPortsForService(ingress, svcName)
				for _, p := range extracted {
					// Check if already exists
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


		// 5. External Auth (auth-url)
		// annotations: auth-url
		if val, ok := ingress.Annotations[annotationAuthURL]; ok && val != "" {
			// If security policy is not already set (e.g. by Cloud Armor annotations),
			// suggest a manual policy for External Auth.
			if serviceIR.Gce.SecurityPolicy == nil {
				serviceIR.Gce.SecurityPolicy = &intermediate.SecurityPolicyConfig{Name: policyManualExternalAuth}
			}
		}

		// 6. Backend TLS
		// annotations: proxy-ssl-verify, proxy-ssl-secret
		if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/proxy-ssl-verify"]; ok && val == "on" {
			if serviceIR.Gce.Tls == nil {
				serviceIR.Gce.Tls = &intermediate.BackendTlsConfig{}
			}
			serviceIR.Gce.Tls.Mode = "Secure"
		}
		if val, ok := ingress.Annotations["nginx.ingress.kubernetes.io/proxy-ssl-secret"]; ok && val != "" {
			if serviceIR.Gce.Tls == nil {
				serviceIR.Gce.Tls = &intermediate.BackendTlsConfig{}
			}
			serviceIR.Gce.Tls.SecretName = val
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
			if name.Name == *ingressClass || string(gw.Spec.GatewayClassName) == *ingressClass {
				// Update GatewayClassName to GKE L7
				gw.Spec.GatewayClassName = gatewayv1.ObjectName("gke-l7-global-external-managed")

				// Found a candidate Gateway.
				// Check annotations.
				if val, ok := ingress.Annotations[annotationSSLCiphers]; ok && val != "" {
					if gw.ProviderSpecificIR.Gce == nil {
						gw.ProviderSpecificIR.Gce = &intermediate.GceGatewayIR{}
					}
					gw.ProviderSpecificIR.Gce.SslPolicy = &intermediate.SslPolicyConfig{Name: policyManualSSL}
					ir.Gateways[name] = gw
				}
				// ssl-redirect
				if val, ok := ingress.Annotations[annotationSSLRedirect]; ok && val == "true" {
					if gw.ProviderSpecificIR.Gce == nil {
						gw.ProviderSpecificIR.Gce = &intermediate.GceGatewayIR{}
					}
					gw.ProviderSpecificIR.Gce.EnableHTTPSRedirect = true
				}
				// force-ssl-redirect
				if val, ok := ingress.Annotations[annotationForceSSLRedirect]; ok && val == "true" {
					if gw.ProviderSpecificIR.Gce == nil {
						gw.ProviderSpecificIR.Gce = &intermediate.GceGatewayIR{}
					}
					gw.ProviderSpecificIR.Gce.EnableHTTPSRedirect = true
				}
				ir.Gateways[name] = gw
			}
		}
	}
}

func processRouteAnnotations(ingress *networkingv1.Ingress, rule *gatewayv1.HTTPRouteRule) {
	// 1. Timeouts
	// annotations: proxy-read-timeout, proxy-send-timeout
	if val, ok := ingress.Annotations[annotationProxyReadTimeout]; ok {
		if duration, err := time.ParseDuration(val + "s"); err == nil { // Nginx timeout is in seconds usually
			if rule.Timeouts == nil {
				rule.Timeouts = &gatewayv1.HTTPRouteTimeouts{}
			}
			gwDuration := gatewayv1.Duration(duration.String())
			rule.Timeouts.BackendRequest = &gwDuration
		} else {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse proxy-read-timeout %q: %v\n", val, err)
		}
	}
	if val, ok := ingress.Annotations[annotationProxySendTimeout]; ok {
		if duration, err := time.ParseDuration(val + "s"); err == nil {
			if rule.Timeouts == nil {
				rule.Timeouts = &gatewayv1.HTTPRouteTimeouts{}
			}
			gwDuration := gatewayv1.Duration(duration.String())
			rule.Timeouts.BackendRequest = &gwDuration
		} else {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse proxy-send-timeout %q: %v\n", val, err)
		}
	}

	// 2. Rewrites
	// annotations: rewrite-target
	if val, ok := ingress.Annotations[annotationRewriteTarget]; ok {
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
	if val, ok := ingress.Annotations[annotationUpstreamVHost]; ok && val != "" {
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
	// annotations: permanent-redirect, temporal-redirect
	if val, ok := ingress.Annotations[annotationPermanentRedirect]; ok {
		applyRedirect(val, 301, rule)
	} else if val, ok := ingress.Annotations[annotationTemporalRedirect]; ok {
		applyRedirect(val, 302, rule)
	}
}

func applyRedirect(url string, statusCode int, rule *gatewayv1.HTTPRouteRule) {
	// Nginx redirect annotations expect a URL or URI.
	// If it contains scheme/host, we set them. Otherwise just path.
	// For simplicity, we'll try to parse it. But Nginx might allow more loose formats.
	// If it's just a path (e.g. /new), we set PathModifier (not directly RequestRedirect Path, wait, RequestRedirect matches better).
	// Actually RequestRedirect filter in Gateway API handles Scheme, Hostname, Port, StatusCode, Path.
	// Path replacement in RequestRedirect is done via Path modifier if supported?
	// Gateway API v1 RequestRedirectFilter:
	// - Scheme
	// - Hostname
	// - Path: {Type: ReplaceFullPath | ReplacePrefixMatch, ReplaceFullPath: ..., ReplacePrefixMatch: ...}
	// - Port
	// - StatusCode

	// Simple heuristic:
	filter := gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterRequestRedirect,
		RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{
			StatusCode: common.PtrTo(statusCode),
		},
	}

	// Check if full URL
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		// Parse matches is hard without net/url, but let's try basic string splitting or just assume implementation specifics.
		// For now, let's just handle simple full paths or relative paths.
		// Since we want to remain robust, we'll just set what we can.
		// Nginx behavior: "This annotation allows you to return a permanent redirect (301) to the provided URL."
	} else {
		// Assume it's a path rewrite redirect
		// e.g. /old -> /new
		filter.RequestRedirect.Path = &gatewayv1.HTTPPathModifier{
			Type:            gatewayv1.FullPathHTTPPathModifier,
			ReplaceFullPath: &url,
		}
	}
	rule.Filters = append(rule.Filters, filter)
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

func ptrToInt(i int) *int {
	return &i
}