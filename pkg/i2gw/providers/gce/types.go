/*
Copyright 2024 The Kubernetes Authors.

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

package gce

import (
	gkegatewayv1 "github.com/GoogleCloudPlatform/gke-gateway-api/apis/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

const (
	gceIngressClass      = "gce"
	gceL7ILBIngressClass = "gce-internal"

	gceL7GlobalExternalManagedGatewayClass = "gke-l7-global-external-managed"
	gceL7RegionalInternalGatewayClass      = "gke-l7-rilb"
	backendConfigKey                       = "cloud.google.com/backend-config"
	betaBackendConfigKey                   = "beta.cloud.google.com/backend-config"
	frontendConfigKey                      = "networking.gke.io/v1beta1.FrontendConfig"
)

var (
	GCPBackendPolicyGVK = schema.GroupVersionKind{
		Group:   "networking.gke.io",
		Version: "v1",
		Kind:    "GCPBackendPolicy",
	}

	GCPGatewayPolicyGVK = schema.GroupVersionKind{
		Group:   "networking.gke.io",
		Version: "v1",
		Kind:    "GCPGatewayPolicy",
	}

	HealthCheckPolicyGVK = schema.GroupVersionKind{
		Group:   "networking.gke.io",
		Version: "v1",
		Kind:    "HealthCheckPolicy",
	}
)

// Local definitions for GKE Gateway API types that might be missing or incomplete in the imported library.

type LocalGCPBackendPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              LocalGCPBackendPolicySpec `json:"spec,omitempty"`
	Status            map[string]interface{}    `json:"status"`
}

type LocalGCPBackendPolicySpec struct {
	Default   *LocalGCPBackendPolicyConfig                    `json:"default,omitempty"`
	TargetRef gatewayv1alpha2.NamespacedPolicyTargetReference `json:"targetRef,omitempty"`
}

type LocalGCPBackendPolicyConfig struct {
	SessionAffinity *gkegatewayv1.SessionAffinityConfig    `json:"sessionAffinity,omitempty"`
	SecurityPolicy  *string                                `json:"securityPolicy,omitempty"`
	IAP             *gkegatewayv1.IdentityAwareProxyConfig `json:"iap,omitempty"`
	LocalityLbPolicy *string                               `json:"localityLbPolicy,omitempty"`
}

func (in *LocalGCPBackendPolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(LocalGCPBackendPolicy)
	*out = *in
	// TODO: Implement full deep copy if needed
	return out
}
