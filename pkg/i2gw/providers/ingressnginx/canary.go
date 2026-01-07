/*
Copyright 2023 The Kubernetes Authors.

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
	"strconv"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/intermediate"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/notifications"
	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/common"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	canaryAnnotation              = "nginx.ingress.kubernetes.io/canary"
	canaryWeightAnnotation        = "nginx.ingress.kubernetes.io/canary-weight"
	canaryWeightTotalAnnotation   = "nginx.ingress.kubernetes.io/canary-weight-total"
	canaryByHeaderAnnotation      = "nginx.ingress.kubernetes.io/canary-by-header"
	canaryByHeaderValueAnnotation = "nginx.ingress.kubernetes.io/canary-by-header-value"
	canaryByCookieAnnotation      = "nginx.ingress.kubernetes.io/canary-by-cookie"
)

// canaryConfig holds the parsed canary configuration from a single Ingress
type canaryConfig struct {
	weight      int32
	weightTotal int32
}

// parseCanaryConfig extracts canary weight configuration from an Ingress
func parseCanaryConfig(ingress *networkingv1.Ingress) (canaryConfig, error) {
	config := canaryConfig{
		weight:      0,
		weightTotal: 100, // default
	}

	if weight := ingress.Annotations[canaryWeightAnnotation]; weight != "" {
		w, err := strconv.ParseInt(weight, 10, 32)
		if err != nil {
			return config, fmt.Errorf("invalid canary-weight annotation %q: %w", weight, err)
		}
		if w < 0 {
			return config, fmt.Errorf("canary-weight must be non-negative, got %d", w)
		}
		config.weight = int32(w)
	}

	if total := ingress.Annotations[canaryWeightTotalAnnotation]; total != "" {
		wt, err := strconv.ParseInt(total, 10, 32)
		if err != nil {
			return config, fmt.Errorf("invalid canary-weight-total annotation %q: %w", total, err)
		}
		if wt <= 0 {
			return config, fmt.Errorf("canary-weight-total must be positive, got %d", wt)
		}
		config.weightTotal = int32(wt)
	}

	if config.weight > config.weightTotal {
		return config, fmt.Errorf("canary-weight (%d) exceeds canary-weight-total (%d)", config.weight, config.weightTotal)
	}

	return config, nil
}

func canaryFeature(ingresses []networkingv1.Ingress, _ map[types.NamespacedName]map[string]int32, ir *intermediate.IR) field.ErrorList {
	ruleGroups := common.GetRuleGroups(ingresses)
	var errList field.ErrorList

	for _, rg := range ruleGroups {
		key := types.NamespacedName{Namespace: rg.Namespace, Name: common.RouteName(rg.Name, rg.Host)}
		httpRouteContext, ok := ir.HTTPRoutes[key]
		if !ok {
			continue
		}

		for ruleIdx, backendSources := range httpRouteContext.RuleBackendSources {
			if ruleIdx >= len(httpRouteContext.HTTPRoute.Spec.Rules) {
				errList = append(errList, field.InternalError(
					field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx),
					fmt.Errorf("rule index %d exceeds available rules", ruleIdx),
				))
				continue
			}

			// There must be a non canary backend and at most one canary backend
			// This is done in place.
			var canaryBackend *gatewayv1.HTTPBackendRef
			var nonCanaryBackend *gatewayv1.HTTPBackendRef
			var canaryConfig canaryConfig
			var canarySourceIngress *networkingv1.Ingress

			// Find the canary and non-canary backends
			for backendIdx, source := range backendSources {
				if source.Ingress == nil {
					continue
				}

				backendRef := &httpRouteContext.HTTPRoute.Spec.Rules[ruleIdx].BackendRefs[backendIdx]

				if source.Ingress.Annotations[canaryAnnotation] == "true" {
					if canaryBackend != nil {
						errList = append(errList, field.Invalid(
							field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx).Child("backendRefs"),
							fmt.Sprintf("ingresses %s/%s and %s/%s", canarySourceIngress.Namespace, canarySourceIngress.Name, source.Ingress.Namespace, source.Ingress.Name),
							"at most one canary backend is allowed per rule",
						))
						continue
					}

					config, err := parseCanaryConfig(source.Ingress)
					if err != nil {
						errList = append(errList, field.Invalid(
							field.NewPath("ingress", source.Ingress.Namespace, source.Ingress.Name, "metadata", "annotations"),
							source.Ingress.Annotations,
							fmt.Sprintf("failed to parse canary configuration: %v", err),
						))
						continue
					}

					canaryBackend = backendRef
					canaryConfig = config
					canarySourceIngress = source.Ingress
				} else {
					if nonCanaryBackend != nil {
						errList = append(errList, field.Invalid(
							field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx).Child("backendRefs"),
							"multiple non-canary backends",
							"at most one non-canary backend is allowed per rule when using canary",
						))
						continue
					}
					nonCanaryBackend = backendRef
				}
			}

			// If there is a canary backend, validate and set weights
			if canaryBackend != nil {
				if nonCanaryBackend == nil {
					errList = append(errList, field.Invalid(
						field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx).Child("backendRefs"),
						"canary backend without non-canary backend",
						"a non-canary backend is required when using canary",
					))
					continue
				}

				canaryWeight := canaryConfig.weight

				canaryBackend.Weight = &canaryWeight
				nonCanaryWeight := canaryConfig.weightTotal - canaryWeight
				nonCanaryBackend.Weight = &nonCanaryWeight

				notify(notifications.InfoNotification, fmt.Sprintf("parsed canary annotations of ingress %s/%s and set weights (canary: %d, non-canary: %d, total: %d)",
					canarySourceIngress.Namespace, canarySourceIngress.Name, canaryWeight, nonCanaryWeight, canaryConfig.weightTotal), &httpRouteContext.HTTPRoute)
			}
		}
	}

	if len(errList) > 0 {
		return errList
	}
	return nil
}

func canaryFeatureGCE(ingresses []networkingv1.Ingress, _ map[types.NamespacedName]map[string]int32, ir *intermediate.IR) field.ErrorList {
	ruleGroups := common.GetRuleGroups(ingresses)
	var errList field.ErrorList

	for _, rg := range ruleGroups {
		key := types.NamespacedName{Namespace: rg.Namespace, Name: common.RouteName(rg.Name, rg.Host)}
		httpRouteContext, ok := ir.HTTPRoutes[key]
		if !ok {
			continue
		}

		var newRules []gatewayv1.HTTPRouteRule
		var newRuleBackendSources [][]intermediate.BackendSource

		for ruleIdx, backendSources := range httpRouteContext.RuleBackendSources {
			if ruleIdx >= len(httpRouteContext.HTTPRoute.Spec.Rules) {
				errList = append(errList, field.InternalError(
					field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx),
					fmt.Errorf("rule index %d exceeds available rules", ruleIdx),
				))
				continue
			}

			originalRule := httpRouteContext.HTTPRoute.Spec.Rules[ruleIdx]

			// There must be a non canary backend and at most one canary backend
			var canaryBackend *gatewayv1.HTTPBackendRef
			var nonCanaryBackend *gatewayv1.HTTPBackendRef
			var canaryConfig canaryConfig
			var canarySourceIngress *networkingv1.Ingress
			var canaryBackendIdx int

			// Find the canary and non-canary backends
			for backendIdx, source := range backendSources {
				if source.Ingress == nil {
					continue
				}

				// We need a pointer to the backend in the original rule to modify it later (for weights)
				// But for splitting rules, we'll use copies.
				backendRef := &originalRule.BackendRefs[backendIdx]

				if source.Ingress.Annotations[canaryAnnotation] == "true" {
					if canaryBackend != nil {
						errList = append(errList, field.Invalid(
							field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx).Child("backendRefs"),
							fmt.Sprintf("ingresses %s/%s and %s/%s", canarySourceIngress.Namespace, canarySourceIngress.Name, source.Ingress.Namespace, source.Ingress.Name),
							"at most one canary backend is allowed per rule",
						))
						continue
					}

					config, err := parseCanaryConfig(source.Ingress)
					if err != nil {
						errList = append(errList, field.Invalid(
							field.NewPath("ingress", source.Ingress.Namespace, source.Ingress.Name, "metadata", "annotations"),
							source.Ingress.Annotations,
							fmt.Sprintf("failed to parse canary configuration: %v", err),
						))
						continue
					}

					canaryBackend = backendRef
					canaryConfig = config
					canarySourceIngress = source.Ingress
					canaryBackendIdx = backendIdx
				} else {
					if nonCanaryBackend != nil {
						errList = append(errList, field.Invalid(
							field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx).Child("backendRefs"),
							"multiple non-canary backends",
							"at most one non-canary backend is allowed per rule when using canary",
						))
						continue
					}
					nonCanaryBackend = backendRef
				}
			}

			// If there is a canary backend, process it
			if canaryBackend != nil {
				if nonCanaryBackend == nil {
					errList = append(errList, field.Invalid(
						field.NewPath("httproute", httpRouteContext.HTTPRoute.Name, "spec", "rules").Index(ruleIdx).Child("backendRefs"),
						"canary backend without non-canary backend",
						"a non-canary backend is required when using canary",
					))
					continue
				}

				// 1. Handle Canary by Header
				if headerName := canarySourceIngress.Annotations[canaryByHeaderAnnotation]; headerName != "" {
					headerValue := "always"
					if val := canarySourceIngress.Annotations[canaryByHeaderValueAnnotation]; val != "" {
						headerValue = val
					}

					// Rule for "always" (or specific value) -> Canary
					canaryRule := originalRule.DeepCopy()
					canaryRule.BackendRefs = []gatewayv1.HTTPBackendRef{*canaryBackend}
					canaryRule.BackendRefs[0].Weight = nil

					if len(canaryRule.Matches) == 0 {
						canaryRule.Matches = []gatewayv1.HTTPRouteMatch{{}}
					}
					for i := range canaryRule.Matches {
						canaryRule.Matches[i].Headers = append(canaryRule.Matches[i].Headers, gatewayv1.HTTPHeaderMatch{
							Name:  gatewayv1.HTTPHeaderName(headerName),
							Value: headerValue,
							Type:  ptrToHeaderMatchType(gatewayv1.HeaderMatchExact),
						})
					}
					newRules = append(newRules, *canaryRule)
					newRuleBackendSources = append(newRuleBackendSources, []intermediate.BackendSource{{Ingress: canarySourceIngress}})

					// Rule for "never" -> Non-Canary (Stable)
					neverRule := originalRule.DeepCopy()
					neverRule.BackendRefs = []gatewayv1.HTTPBackendRef{*nonCanaryBackend}
					neverRule.BackendRefs[0].Weight = nil

					if len(neverRule.Matches) == 0 {
						neverRule.Matches = []gatewayv1.HTTPRouteMatch{{}}
					}
					for i := range neverRule.Matches {
						neverRule.Matches[i].Headers = append(neverRule.Matches[i].Headers, gatewayv1.HTTPHeaderMatch{
							Name:  gatewayv1.HTTPHeaderName(headerName),
							Value: "never",
							Type:  ptrToHeaderMatchType(gatewayv1.HeaderMatchExact),
						})
					}
					newRules = append(newRules, *neverRule)
					// Source for "never" rule is technically the stable ingress, but we can attribute it to the canary ingress logic or keep original sources minus canary.
					// Using original sources is safer for context, but we only route to non-canary.
					// Let's use the non-canary source(s).
					var nonCanarySources []intermediate.BackendSource
					for idx, src := range backendSources {
						if idx != canaryBackendIdx { // exclude canary source
							nonCanarySources = append(nonCanarySources, src)
						}
					}
					newRuleBackendSources = append(newRuleBackendSources, nonCanarySources)

					notify(notifications.InfoNotification, fmt.Sprintf("parsed canary-by-header annotation of ingress %s/%s",
						canarySourceIngress.Namespace, canarySourceIngress.Name), &httpRouteContext.HTTPRoute)
				}

				// 2. Handle Canary by Cookie
				if cookieName := canarySourceIngress.Annotations[canaryByCookieAnnotation]; cookieName != "" {
					// Rule for "always" -> Canary
					canaryRule := originalRule.DeepCopy()
					canaryRule.BackendRefs = []gatewayv1.HTTPBackendRef{*canaryBackend}
					canaryRule.BackendRefs[0].Weight = nil

					regexAlways := fmt.Sprintf(`(^|; ?)%s=always(; ?|$)`, cookieName)

					if len(canaryRule.Matches) == 0 {
						canaryRule.Matches = []gatewayv1.HTTPRouteMatch{{}}
					}
					for i := range canaryRule.Matches {
						canaryRule.Matches[i].Headers = append(canaryRule.Matches[i].Headers, gatewayv1.HTTPHeaderMatch{
							Name:  "Cookie",
							Value: regexAlways,
							Type:  ptrToHeaderMatchType(gatewayv1.HeaderMatchRegularExpression),
						})
					}
					newRules = append(newRules, *canaryRule)
					newRuleBackendSources = append(newRuleBackendSources, []intermediate.BackendSource{{Ingress: canarySourceIngress}})

					// Rule for "never" -> Non-Canary (Stable)
					neverRule := originalRule.DeepCopy()
					neverRule.BackendRefs = []gatewayv1.HTTPBackendRef{*nonCanaryBackend}
					neverRule.BackendRefs[0].Weight = nil

					regexNever := fmt.Sprintf(`(^|; ?)%s=never(; ?|$)`, cookieName)

					if len(neverRule.Matches) == 0 {
						neverRule.Matches = []gatewayv1.HTTPRouteMatch{{}}
					}
					for i := range neverRule.Matches {
						neverRule.Matches[i].Headers = append(neverRule.Matches[i].Headers, gatewayv1.HTTPHeaderMatch{
							Name:  "Cookie",
							Value: regexNever,
							Type:  ptrToHeaderMatchType(gatewayv1.HeaderMatchRegularExpression),
						})
					}
					newRules = append(newRules, *neverRule)
					
					var nonCanarySources []intermediate.BackendSource
					for idx, src := range backendSources {
						if idx != canaryBackendIdx {
							nonCanarySources = append(nonCanarySources, src)
						}
					}
					newRuleBackendSources = append(newRuleBackendSources, nonCanarySources)

					notify(notifications.InfoNotification, fmt.Sprintf("parsed canary-by-cookie annotation of ingress %s/%s",
						canarySourceIngress.Namespace, canarySourceIngress.Name), &httpRouteContext.HTTPRoute)
				}

				// 3. Handle Weighted (Fallback)
				// Even if header/cookie is used, the original rule remains as fallback.
				// If canary-weight is not explicitly set, it defaults to 0, so fallback is 100% stable.
				// If canary-weight IS set, it splits traffic for requests NOT matching header/cookie.

				canaryWeight := canaryConfig.weight
				canaryBackend.Weight = &canaryWeight
				nonCanaryWeight := canaryConfig.weightTotal - canaryWeight
				nonCanaryBackend.Weight = &nonCanaryWeight

				newRules = append(newRules, originalRule)
				newRuleBackendSources = append(newRuleBackendSources, backendSources)

				notify(notifications.InfoNotification, fmt.Sprintf("parsed canary annotations of ingress %s/%s and set weights (canary: %d, non-canary: %d, total: %d)",
					canarySourceIngress.Namespace, canarySourceIngress.Name, canaryWeight, nonCanaryWeight, canaryConfig.weightTotal), &httpRouteContext.HTTPRoute)

			} else {
				// No canary, keep original
				newRules = append(newRules, originalRule)
				newRuleBackendSources = append(newRuleBackendSources, backendSources)
			}
		}

		// Update the HTTPRoute with the new rules
		httpRouteContext.HTTPRoute.Spec.Rules = newRules
		httpRouteContext.RuleBackendSources = newRuleBackendSources
		ir.HTTPRoutes[key] = httpRouteContext
	}

	if len(errList) > 0 {
		return errList
	}
	return nil
}

func ptrToHeaderMatchType(t gatewayv1.HeaderMatchType) *gatewayv1.HeaderMatchType {
	return &t
}
