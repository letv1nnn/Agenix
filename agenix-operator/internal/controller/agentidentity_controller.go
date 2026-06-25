/*
Copyright 2026.

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

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	agentv1alpha1 "github.com/Bobbins228/Agenix/agenix-operator/api/v1alpha1"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/certutil"
)

const (
	conditionCertificateReady = "CertificateReady"
	phaseError                = "Error"
)

// AgentIdentityReconciler reconciles a AgentIdentity object
type AgentIdentityReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	CA     *ca.CA
}

// +kubebuilder:rbac:groups=agent.agenix.io,resources=agentidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agent.agenix.io,resources=agentidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agent.agenix.io,resources=agentidentities/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AgentIdentity object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/reconcile
func (r *AgentIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the AgentIdentity CR
	identity := &agentv1alpha1.AgentIdentity{}
	if err := r.Get(ctx, req.NamespacedName, identity); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if the target Deployment exists
	deployment := &appsv1.Deployment{}
	deploymentName := types.NamespacedName{
		Name:      identity.Spec.TargetRef.Name,
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, deploymentName, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			identity.Status.Phase = phaseError
			meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
				Type:               "TargetFound",
				Status:             metav1.ConditionFalse,
				Reason:             "DeploymentNotFound",
				Message:            fmt.Sprintf("Deployment %q not found in namespace %q", identity.Spec.TargetRef.Name, req.Namespace),
				LastTransitionTime: metav1.Now(),
			})
			if err := r.Status().Update(ctx, identity); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	identity.Status.Phase = "Pending"
	meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
		Type:               "TargetFound",
		Status:             metav1.ConditionTrue,
		Reason:             "DeploymentFound",
		Message:            fmt.Sprintf("Deployment %q found", identity.Spec.TargetRef.Name),
		LastTransitionTime: metav1.Now(),
	})
	log.Info("Target Deployment found", "deployment", identity.Spec.TargetRef.Name, "serviceAccount",
		deployment.Spec.Template.Spec.ServiceAccountName)

	serviceAccount := deployment.Spec.Template.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}

	spiffeID, err := certutil.GenerateSPIFFEID(
		identity.Spec.Identity.TrustDomain,
		req.Namespace,
		serviceAccount,
	)
	if err != nil {
		log.Error(err, "Failed to generate SPIFFE ID")
		identity.Status.Phase = phaseError
		meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
			Type:               conditionCertificateReady,
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidSPIFFEID",
			Message:            fmt.Sprintf("Failed to generate SPIFFE ID: %v", err),
			LastTransitionTime: metav1.Now(),
		})
		if statusErr := r.Status().Update(ctx, identity); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, nil
	}
	log.Info("SPIFFE ID generated", "spiffeID", spiffeID)

	existingSecret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      identity.Name + "-tls",
		Namespace: identity.Namespace,
	}, existingSecret)
	if err == nil {
		block, _ := pem.Decode(existingSecret.Data["tls.crt"])
		if block != nil {
			existingCert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr == nil && time.Now().Before(existingCert.NotAfter) {
				log.Info("Certificate still valid, skipping regeneration", "notAfter", existingCert.NotAfter)
				fingerprint, fpErr := certutil.ComputeFingerprint(existingSecret.Data["tls.crt"])
				if fpErr != nil {
					return ctrl.Result{}, fpErr
				}
				identity.Status.Phase = "Provisioned"
				identity.Status.AgentID = spiffeID
				identity.Status.Certificate = &agentv1alpha1.CertificateInfo{
					SerialNumber: existingCert.SerialNumber.Text(16),
					NotBefore:    metav1.NewTime(existingCert.NotBefore),
					NotAfter:     metav1.NewTime(existingCert.NotAfter),
					Fingerprint:  fingerprint,
				}
				meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
					Type:               conditionCertificateReady,
					Status:             metav1.ConditionTrue,
					Reason:             "CertificateIssued",
					Message:            fmt.Sprintf("X.509 certificate issued and stored in Secret %s-tls", identity.Name),
					LastTransitionTime: metav1.Now(),
				})
				if err := r.Status().Update(ctx, identity); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{RequeueAfter: time.Until(existingCert.NotAfter) * 2 / 3}, nil
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	ttl, err := time.ParseDuration(identity.Spec.Identity.TTL)
	if err != nil {
		log.Error(err, "Failed to parse TTL", "ttl", identity.Spec.Identity.TTL)
		identity.Status.Phase = phaseError
		meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
			Type:               conditionCertificateReady,
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidTTL",
			Message:            fmt.Sprintf("Failed to parse TTL %q: %v", identity.Spec.Identity.TTL, err),
			LastTransitionTime: metav1.Now(),
		})
		if statusErr := r.Status().Update(ctx, identity); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, nil
	}
	bundle, err := certutil.GenerateAgentCertificate(r.CA, spiffeID, ttl)
	if err != nil {
		log.Error(err, "Failed to generate certificate")
		identity.Status.Phase = phaseError
		meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
			Type:               conditionCertificateReady,
			Status:             metav1.ConditionFalse,
			Reason:             "CertificateGenerationFailed",
			Message:            fmt.Sprintf("Failed to generate certificate: %v", err),
			LastTransitionTime: metav1.Now(),
		})
		if statusErr := r.Status().Update(ctx, identity); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, nil
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identity.Name + "-tls",
			Namespace: identity.Namespace,
		},
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			"tls.crt": bundle.CertPEM,
			"tls.key": bundle.KeyPEM,
			"ca.crt":  bundle.CaCertPEM,
		}
		return controllerutil.SetControllerReference(identity, secret, r.Scheme)
	})
	if err != nil {
		log.Error(err, "Failed to create or update Secret")
		return ctrl.Result{}, err
	}

	log.Info("Certificate Secret created", "secret", secret.Name)

	identity.Status.Phase = "Provisioned"
	identity.Status.AgentID = spiffeID
	identity.Status.Certificate = &agentv1alpha1.CertificateInfo{
		SerialNumber: bundle.SerialNumber,
		NotBefore:    metav1.NewTime(bundle.NotBefore),
		NotAfter:     metav1.NewTime(bundle.NotAfter),
		Fingerprint:  bundle.Fingerprint,
	}
	meta.SetStatusCondition(&identity.Status.Conditions, metav1.Condition{
		Type:               conditionCertificateReady,
		Status:             metav1.ConditionTrue,
		Reason:             "CertificateIssued",
		Message:            fmt.Sprintf("X.509 certificate issued and stored in Secret %s-tls", identity.Name),
		LastTransitionTime: metav1.Now(),
	})
	if err := r.Status().Update(ctx, identity); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: ttl * 2 / 3}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&agentv1alpha1.AgentIdentity{}).
		Owns(&corev1.Secret{}).
		Named("agentidentity").
		Complete(r)
}
