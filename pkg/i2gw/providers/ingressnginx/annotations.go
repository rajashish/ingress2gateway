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

const (
	// Canary annotations
	CanaryAnnotation            = "nginx.ingress.kubernetes.io/canary"
	CanaryWeightAnnotation      = "nginx.ingress.kubernetes.io/canary-weight"
	CanaryWeightTotalAnnotation = "nginx.ingress.kubernetes.io/canary-weight-total"

	// Rewrite annotations
	RewriteTargetAnnotation = "nginx.ingress.kubernetes.io/rewrite-target"

	// Header annotations
	XForwardedPrefixAnnotation      = "nginx.ingress.kubernetes.io/x-forwarded-prefix"
	UpstreamVhostAnnotation         = "nginx.ingress.kubernetes.io/upstream-vhost"
	ConnectionProxyHeaderAnnotation = "nginx.ingress.kubernetes.io/connection-proxy-header"
	CustomHeadersAnnotation         = "nginx.ingress.kubernetes.io/custom-headers"

	// Affinity annotations
	AffinityAnnotation             = "nginx.ingress.kubernetes.io/affinity"
	AffinityModeAnnotation         = "nginx.ingress.kubernetes.io/affinity-mode"
	SessionCookieNameAnnotation    = "nginx.ingress.kubernetes.io/session-cookie-name"
	SessionCookieHashAnnotation    = "nginx.ingress.kubernetes.io/session-cookie-hash"
	SessionCookieExpiresAnnotation = "nginx.ingress.kubernetes.io/session-cookie-expires"

	// Security annotations
	WhitelistSourceRangeAnnotation = "nginx.ingress.kubernetes.io/whitelist-source-range"
	LimitRPSAnnotation             = "nginx.ingress.kubernetes.io/limit-rps"

	// Auth annotations
	EnableGlobalAuthAnnotation = "nginx.ingress.kubernetes.io/enable-global-auth"
	AuthSecretAnnotation       = "nginx.ingress.kubernetes.io/auth-secret"

	// SSL Redirect annotations
	SSLRedirectAnnotation      = "nginx.ingress.kubernetes.io/ssl-redirect"
	ForceSSLRedirectAnnotation = "nginx.ingress.kubernetes.io/force-ssl-redirect"
)
