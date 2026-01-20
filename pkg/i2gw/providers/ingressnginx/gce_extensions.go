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

	"time"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	providerir "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func gceFeature(ingresses []networkingv1.Ingress, _ map[types.NamespacedName]map[string]int32, ir *providerir.ProviderIR) field.ErrorList {
	var errs field.ErrorList

	for _, ingress := range ingresses {
		processSessionAffinity(ingress, ir)
		processSecurityPolicy(ingress, ir)
		processIAP(ingress, ir)
		processSSLRedirect(ingress, ir)
		processTimeouts(ingress, ir)
		processBackendProtocol(ingress, ir)
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

func processSecurityPolicy(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	var policyName string
	if _, ok := ingress.Annotations[LimitRPSAnnotation]; ok {
		policyName = "manual-cloud-armor-policy-required-ratelimit"
	}

	// Whitelist annotation implies a specific naming convention if not overridden by limit-rps (or maybe they coexist? GKE BackendPolicy only allows one SecurityPolicy).
	// Assuming limit-rps takes precedence or they are mutually exclusive in usage for this tool.
	// If limit-rps is NOT present, check whitelist.
	if policyName == "" {
		if _, ok := ingress.Annotations[WhitelistSourceRangeAnnotation]; !ok {
			return
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

		finalPolicyName := policyName
		if finalPolicyName == "" {
			finalPolicyName = "whitelist-" + svcName.Name
		}

		svcIR.Gce.SecurityPolicy = &gce.SecurityPolicyConfig{
			Name: finalPolicyName,
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

func processIAP(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	authSecret, hasSecret := ingress.Annotations[AuthSecretAnnotation]
	enableAuth, hasEnable := ingress.Annotations[EnableGlobalAuthAnnotation]

	if !hasSecret && (!hasEnable || enableAuth != "true") {
		return
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

		iapConfig := &gce.IAPConfig{
			Enabled: true,
		}
		if hasSecret {
			iapConfig.OAuth2ClientSecret = &gce.OAuth2ClientSecret{
				Name: authSecret,
			}
		}

		svcIR.Gce.IAP = iapConfig
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

func processSSLRedirect(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	sslRedirect, _ := ingress.Annotations[SSLRedirectAnnotation]
	forceSSLRedirect, _ := ingress.Annotations[ForceSSLRedirectAnnotation]

	if sslRedirect != "true" && forceSSLRedirect != "true" {
		return
	}

	ingressClass := "nginx"
	if ingress.Spec.IngressClassName != nil {
		ingressClass = *ingress.Spec.IngressClassName
	}

	gwName := types.NamespacedName{
		Namespace: ingress.Namespace,
		Name:      ingressClass,
	}

	if gwCtx, ok := ir.Gateways[gwName]; ok {
		if gwCtx.ProviderSpecificIR.Gce == nil {
			gwCtx.ProviderSpecificIR.Gce = &gce.GatewayIR{}
		}
		gwCtx.ProviderSpecificIR.Gce.EnableHTTPSRedirect = true
		ir.Gateways[gwName] = gwCtx
	}
}

func processTimeouts(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	readTimeout, hasRead := ingress.Annotations[ProxyReadTimeoutAnnotation]
	sendTimeout, hasSend := ingress.Annotations[ProxySendTimeoutAnnotation]

	if !hasRead && !hasSend {
		return
	}

	var timeoutVal string
	if hasRead {
		timeoutVal = readTimeout
	} else {
		timeoutVal = sendTimeout
	}

	// Parse timeout
	// Nginx timeout is in seconds by default if no unit.
	// Gateway API expects Duration format (e.g. "1h", "1m", "1s").

	// Check if it has unit
	// Simple check: if it's just digits, append "s"
	isDigits := true
	for _, c := range timeoutVal {
		if c < '0' || c > '9' {
			isDigits = false
			break
		}
	}
	if isDigits {
		timeoutVal += "s"
	}

	duration, err := time.ParseDuration(timeoutVal)
	if err != nil {
		return // Ignore invalid duration
	}
	gwDuration := gatewayv1.Duration(duration.String())

	// Apply to all HTTPRoutes derived from this Ingress
	for key, routeCtx := range ir.HTTPRoutes {
		modified := false
		for i, ruleSources := range routeCtx.RuleBackendSources {
			for _, source := range ruleSources {
				if source.Ingress != nil && source.Ingress.Name == ingress.Name && source.Ingress.Namespace == ingress.Namespace {
					// Found a rule derived from this Ingress
					if routeCtx.HTTPRoute.Spec.Rules[i].Timeouts == nil {
						routeCtx.HTTPRoute.Spec.Rules[i].Timeouts = &gatewayv1.HTTPRouteTimeouts{}
					}
					routeCtx.HTTPRoute.Spec.Rules[i].Timeouts.BackendRequest = &gwDuration
					modified = true
					break // Apply once per rule is enough
				}
			}
		}
		if modified {
			ir.HTTPRoutes[key] = routeCtx
		}
	}
}

func processBackendProtocol(ingress networkingv1.Ingress, ir *providerir.ProviderIR) {
	protocol, ok := ingress.Annotations[BackendProtocolAnnotation]
	if !ok {
		return
	}

	// Map Nginx protocol to GKE protocol
	// Nginx: HTTP, HTTPS, GRPC, GRPCS, AJP, FCGI
	// GKE: HTTP, HTTPS, HTTP2
	var gkeProtocol string
	switch protocol {
	case "HTTPS":
		gkeProtocol = "HTTPS"
	case "GRPC":
		gkeProtocol = "HTTP2"
	case "HTTP2":
		gkeProtocol = "HTTP2"
	default:
		return // Ignore others or default to HTTP (which is default anyway)
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

		// Set HealthCheck config
		if svcIR.Gce.HealthCheck == nil {
			svcIR.Gce.HealthCheck = &gce.HealthCheckConfig{}
		}
		svcIR.Gce.HealthCheck.Type = &gkeProtocol
		
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
