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
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	agentv1alpha1 "github.com/Bobbins228/Agenix/agenix-operator/api/v1alpha1"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/certutil"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/verify"
)

const (
	phaseError                = "Error"
	phaseExpired              = "Expired"
	phaseVerified             = "Verified"
	labelIdentityVerified     = "agenix.io/identity-verified"
	labelAgentID              = "agenix.io/agent-id"
	annotationCertFingerprint = "agenix.io/cert-fingerprint"
	conditionCertificateReady = "CertificateReady"
	conditionIdentityVerified = "IdentityVerified"
	conditionTargetFound      = "TargetFound"
)

const agentIdentityFinalizer string = "agenix.io/identity-cleanup"

// AgentIdentityReconciler reconciles a AgentIdentity object
type AgentIdentityReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	CA       *ca.CA
	Recorder events.EventRecorder
}

// helper to sanitize spiffe id for use in labels (replace "://", "/", with "-")
func SanitizeSPIFFEIDForLabel(spiffeID string) string {
	s := strings.ReplaceAll(spiffeID, "://", "-")
	s = strings.ReplaceAll(s, "/", "-")
	if len(s) > 63 {
		s = s[:63]
		// trim trailing non-alphanumeric if truncation broke the rules
		s = strings.TrimRight(s, "-_.")
	}
	return s
}

// +kubebuilder:rbac:groups=agent.agenix.io,resources=agentidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agent.agenix.io,resources=agentidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agent.agenix.io,resources=agentidentities/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
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
	logger := log.FromContext(ctx)

	// Fetch the AgentIdentity CR
	identity := &agentv1alpha1.AgentIdentity{}
	if err := r.Get(ctx, req.NamespacedName, identity); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("AgentIdentity not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// checking whether the finalizer string already exists on CR
	// and if it does not, we are adding it to the CR and updating the CR in the cluster
	if !controllerutil.ContainsFinalizer(identity, agentIdentityFinalizer) {
		controllerutil.AddFinalizer(identity, agentIdentityFinalizer)
		if err := r.Update(ctx, identity); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if !identity.DeletionTimestamp.IsZero() {
		logger.Info("AgentIdentity is being deleted, handling cleanup")
		return r.handleDeletion(ctx, identity)
	}

	// Check if the target Deployment exists
	deployment := &appsv1.Deployment{}
	deploymentName := types.NamespacedName{
		Name:      identity.Spec.TargetRef.Name,
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, deploymentName, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return r.reportPhaseError(
				ctx,
				identity,
				conditionTargetFound,
				"DeploymentNotFound",
				fmt.Sprintf("Deployment %q not found in namespace %q", identity.Spec.TargetRef.Name, req.Namespace),
			)
		}
		return ctrl.Result{}, err
	}

	identity.Status.Phase = "Pending"
	SetCondition(
		&identity.Status.Conditions,
		conditionTargetFound,
		metav1.ConditionTrue,
		"DeploymentFound",
		fmt.Sprintf("Deployment %q found", identity.Spec.TargetRef.Name),
	)
	logger.Info("Target Deployment found", "deployment", identity.Spec.TargetRef.Name, "serviceAccount",
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
		logger.Error(err, "Failed to generate SPIFFE ID")
		return r.reportPhaseError(
			ctx,
			identity,
			conditionCertificateReady,
			"InvalidSPIFFEID",
			fmt.Sprintf("Failed to generate SPIFFE ID: %v", err),
		)
	}
	logger.Info("SPIFFE ID generated", "spiffeID", spiffeID)

	existingSecret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      identity.Name + "-tls",
		Namespace: identity.Namespace,
	}, existingSecret)
	if err == nil {
		if result, handled, handleErr := r.reconcileExistingSecret(ctx, identity, existingSecret, spiffeID); handled {
			return result, handleErr
		}
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	ttl, err := time.ParseDuration(identity.Spec.Identity.TTL)
	if err != nil {
		logger.Error(err, "Failed to parse TTL", "ttl", identity.Spec.Identity.TTL)
		return r.reportPhaseError(
			ctx,
			identity,
			conditionCertificateReady,
			"InvalidTTL",
			fmt.Sprintf("Failed to parse TTL %q: %v", identity.Spec.Identity.TTL, err),
		)
	}
	bundle, err := certutil.GenerateAgentCertificate(r.CA, spiffeID, ttl)
	if err != nil {
		logger.Error(err, "Failed to generate certificate")
		return r.reportPhaseError(
			ctx,
			identity,
			conditionCertificateReady,
			"CertificateGenerationFailed",
			fmt.Sprintf("Failed to generate certificate: %v", err),
		)
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
		logger.Error(err, "Failed to create or update Secret")
		return ctrl.Result{}, err
	}

	logger.Info("Certificate Secret created", "secret", secret.Name)

	certInfo := &agentv1alpha1.CertificateInfo{
		SerialNumber: bundle.SerialNumber,
		NotBefore:    metav1.NewTime(bundle.NotBefore),
		NotAfter:     metav1.NewTime(bundle.NotAfter),
		Fingerprint:  bundle.Fingerprint,
	}

	SetCondition(
		&identity.Status.Conditions,
		conditionCertificateReady,
		metav1.ConditionTrue,
		"CertificateIssued",
		fmt.Sprintf("X.509 certificate issued and stored in Secret %s-tls", identity.Name),
	)

	return r.verifyAndUpdateStatus(
		ctx,
		identity,
		secret.Data["tls.crt"],
		secret.Data["ca.crt"],
		spiffeID,
		certInfo,
	)
}

func (r *AgentIdentityReconciler) reportPhaseError(
	// helper extracted by Cursor to fix lint issues
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
	conditionType, reason, message string,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	identity.Status.Phase = phaseError
	SetCondition(
		&identity.Status.Conditions,
		conditionType,
		metav1.ConditionFalse,
		reason,
		message,
	)
	if err := r.Status().Update(ctx, identity); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.removeVerificationLabels(ctx, identity); err != nil {
		logger.Error(err, "Failed to remove verification labels")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *AgentIdentityReconciler) reconcileExistingSecret(
	// helper extracted by Cursor to fix lint issues
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
	secret *corev1.Secret,
	spiffeID string,
) (ctrl.Result, bool, error) {
	logger := log.FromContext(ctx)

	block, _ := pem.Decode(secret.Data["tls.crt"])
	if block == nil {
		return ctrl.Result{}, false, nil
	}

	existingCert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		return ctrl.Result{}, false, nil
	}

	fingerprint, fpErr := certutil.ComputeFingerprint(secret.Data["tls.crt"])
	if fpErr != nil {
		return ctrl.Result{}, true, fpErr
	}

	certInfo := &agentv1alpha1.CertificateInfo{
		SerialNumber: existingCert.SerialNumber.Text(16),
		NotBefore:    metav1.NewTime(existingCert.NotBefore),
		NotAfter:     metav1.NewTime(existingCert.NotAfter),
		Fingerprint:  fingerprint,
	}

	caCertPEM := secret.Data["ca.crt"]
	if len(caCertPEM) == 0 {
		logger.Error(nil, "Secret missing ca.crt", "secret", secret.Name)
		identity.Status.AgentID = spiffeID
		result, err := r.reportPhaseError(
			ctx,
			identity,
			conditionCertificateReady,
			"MissingCACertificate",
			fmt.Sprintf("Secret %q is missing ca.crt", secret.Name),
		)
		return result, true, err
	}

	if time.Now().Before(existingCert.NotAfter) {
		logger.Info("Certificate still valid, skipping regeneration", "notAfter", existingCert.NotAfter)
		SetCondition(
			&identity.Status.Conditions,
			conditionCertificateReady,
			metav1.ConditionTrue,
			"CertificateIssued",
			fmt.Sprintf("X.509 certificate stored in Secret %s-tls", identity.Name),
		)
		result, err := r.verifyAndUpdateStatus(ctx, identity, secret.Data["tls.crt"], caCertPEM, spiffeID, certInfo)
		return result, true, err
	}

	if identity.Spec.Identity.AutoRotate {
		logger.Info("Certificate expired, regenerating", "notAfter", existingCert.NotAfter)
		return ctrl.Result{}, false, nil
	}

	logger.Info("Certificate expired, reporting expired status", "notAfter", existingCert.NotAfter)
	result, err := r.verifyAndUpdateStatus(ctx, identity, secret.Data["tls.crt"], caCertPEM, spiffeID, certInfo)
	return result, true, err
}

func (r *AgentIdentityReconciler) handleDeletion(ctx context.Context, ai *agentv1alpha1.AgentIdentity) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Delete TLS Secret
	secretName, secret := ai.Name+"-tls", &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: ai.Namespace}, secret)
	if err == nil {
		if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "Failed to delete TLS Secret", "secret", secretName)
			r.Recorder.Eventf(ai, nil, "Warning", "CleanupFailed", "Cleanup", "Failed to delete TLS Secret: "+err.Error())
			return ctrl.Result{}, err
		}
		logger.Info("Deleted TLS Secret", "secret", secretName)
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	// 2. Remove identity labels from Deployment
	if err := r.removeVerificationLabels(ctx, ai); err != nil {
		logger.Error(err, "Failed to remove verification labels")
		r.Recorder.Eventf(ai, nil, "Warning", "CleanupFailed", "Cleanup", "Failed to remove identity labels: "+err.Error())
		return ctrl.Result{}, err
	}

	// 3. Delete target Deployment
	if err := r.deleteTargetDeployment(ctx, ai); err != nil {
		logger.Error(err, "Failed to delete target Deployment")
		r.Recorder.Eventf(ai, nil, "Warning", "CleanupFailed", "Cleanup", "Failed to delete Deployment: "+err.Error())
		return ctrl.Result{}, err
	}

	// 4. Remove finalizer only after all cleanup succeeds
	controllerutil.RemoveFinalizer(ai, agentIdentityFinalizer)
	if err := r.Update(ctx, ai); err != nil {
		logger.Error(err, "Failed to remove finalizer from AgentIdentity", "agentidentity", ai.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AgentIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&agentv1alpha1.AgentIdentity{}).
		Owns(&corev1.Secret{}).
		Named("agentidentity").
		Complete(r)
}

// helper to check verification and update the status
func (r *AgentIdentityReconciler) verifyAndUpdateStatus(
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
	certPEM, caCertPEM []byte,
	expectedSPIFFEID string,
	certInfo *agentv1alpha1.CertificateInfo,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	result, err := verify.ValidateIdentity(certPEM, caCertPEM, expectedSPIFFEID)
	if err != nil {
		reason := "ChainValidationFailed"
		if result != nil && result.ChainValid && !result.SPIFFEIDMatch {
			reason = "SPIFFEIDMismatch"
		}
		if result == nil {
			reason = "CertificateParseFailed"
		}

		logger.Error(err, "Certificate verification failed")
		identity.Status.Phase = phaseError
		identity.Status.AgentID = expectedSPIFFEID
		identity.Status.Certificate = certInfo
		SetCondition(
			&identity.Status.Conditions,
			conditionIdentityVerified,
			metav1.ConditionFalse,
			reason,
			err.Error(),
		)
		if statusErr := r.Status().Update(ctx, identity); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		if labelErr := r.removeVerificationLabels(ctx, identity); labelErr != nil {
			logger.Error(labelErr, "Failed to remove verification labels")
			return ctrl.Result{}, labelErr
		}
		return ctrl.Result{}, nil
	}

	if result.IsExpired {
		identity.Status.Phase = phaseExpired
		identity.Status.AgentID = expectedSPIFFEID
		identity.Status.Certificate = certInfo
		SetCondition(
			&identity.Status.Conditions,
			conditionCertificateReady,
			metav1.ConditionFalse,
			"CertificateExpired",
			fmt.Sprintf("Certificate expired at %s", result.ExpiresAt.Format(time.RFC3339)),
		)
		if statusErr := r.Status().Update(ctx, identity); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		if labelErr := r.removeVerificationLabels(ctx, identity); labelErr != nil {
			logger.Error(labelErr, "Failed to remove verification labels")
			return ctrl.Result{}, labelErr
		}
		return ctrl.Result{}, nil
	}

	if !result.ChainValid || !result.SPIFFEIDMatch {
		reason := ""
		if !result.ChainValid {
			reason = "ChainValidationFailed"
		}
		if !result.SPIFFEIDMatch {
			reason = "SPIFFEIDMismatch"
		}
		identity.Status.Phase = phaseError
		identity.Status.AgentID = expectedSPIFFEID
		identity.Status.Certificate = certInfo
		SetCondition(
			&identity.Status.Conditions,
			conditionIdentityVerified,
			metav1.ConditionFalse,
			reason,
			fmt.Sprintf("chainValid=%t spiffeIDMatch=%t", result.ChainValid, result.SPIFFEIDMatch),
		)
		if statusErr := r.Status().Update(ctx, identity); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		if labelErr := r.removeVerificationLabels(ctx, identity); labelErr != nil {
			logger.Error(labelErr, "Failed to remove verification labels")
			return ctrl.Result{}, labelErr
		}
		return ctrl.Result{}, nil
	}

	identity.Status.Phase = phaseVerified
	identity.Status.AgentID = expectedSPIFFEID
	identity.Status.Certificate = certInfo
	SetCondition(
		&identity.Status.Conditions,
		conditionIdentityVerified,
		metav1.ConditionTrue,
		"SignatureValid",
		fmt.Sprintf("Certificate chain and SPIFFE ID verified for %s", expectedSPIFFEID),
	)
	if err := r.Status().Update(ctx, identity); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.applyVerificationLabels(ctx, identity, expectedSPIFFEID); err != nil {
		logger.Error(err, "Failed to apply verification labels")
		return ctrl.Result{}, err
	}

	if err := r.triggerIdentityRollout(ctx, identity, certInfo.Fingerprint); err != nil {
		logger.Error(err, "Failed to trigger identity rollout")
		return ctrl.Result{}, err
	}

	requeueAfter := time.Until(result.ExpiresAt) * 2 / 3
	if requeueAfter <= 0 {
		requeueAfter = time.Minute
	}
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// helper to add labels
func (r *AgentIdentityReconciler) applyVerificationLabels(
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
	spiffeID string,
) error {
	deployment := &appsv1.Deployment{}
	key := types.NamespacedName{
		Name:      identity.Spec.TargetRef.Name,
		Namespace: identity.Namespace,
	}
	if err := r.Get(ctx, key, deployment); err != nil {
		return err
	}

	sanitized := SanitizeSPIFFEIDForLabel(spiffeID)
	if deployment.Labels != nil &&
		deployment.Labels[labelIdentityVerified] == "true" &&
		deployment.Labels[labelAgentID] == sanitized {
		return nil
	}

	if deployment.Labels == nil {
		deployment.Labels = map[string]string{}
	}
	deployment.Labels[labelIdentityVerified] = "true"
	deployment.Labels[labelAgentID] = sanitized

	return r.Update(ctx, deployment)
}

// triggerIdentityRollout patches the Deployment pod template so Kubernetes
// recreates pods and the mutating webhook can inject identity material.
func (r *AgentIdentityReconciler) triggerIdentityRollout(
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
	fingerprint string,
) error {
	if fingerprint == "" {
		return nil
	}

	deployment, err := r.getTargetDeployment(ctx, identity)
	if err != nil {
		return err
	}
	if deployment == nil {
		return nil
	}

	if deployment.Spec.Template.Annotations != nil &&
		deployment.Spec.Template.Annotations[annotationCertFingerprint] == fingerprint {
		return nil
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations[annotationCertFingerprint] = fingerprint

	return r.Update(ctx, deployment)
}

// helper to remove labels
func (r *AgentIdentityReconciler) getTargetDeployment(
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
) (*appsv1.Deployment, error) {
	deployment := &appsv1.Deployment{}
	key := types.NamespacedName{
		Name:      identity.Spec.TargetRef.Name,
		Namespace: identity.Namespace,
	}
	if err := r.Get(ctx, key, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return deployment, nil
}

func (r *AgentIdentityReconciler) removeVerificationLabels(
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
) error {
	deployment, err := r.getTargetDeployment(ctx, identity)
	if err != nil {
		return err
	}
	if deployment == nil {
		return nil
	}

	if deployment.Labels == nil {
		return nil
	}

	changed := false
	if _, ok := deployment.Labels[labelIdentityVerified]; ok {
		delete(deployment.Labels, labelIdentityVerified)
		changed = true
	}
	if _, ok := deployment.Labels[labelAgentID]; ok {
		delete(deployment.Labels, labelAgentID)
		changed = true
	}
	if !changed {
		return nil
	}

	return r.Update(ctx, deployment)
}

func (r *AgentIdentityReconciler) deleteTargetDeployment(
	ctx context.Context,
	identity *agentv1alpha1.AgentIdentity,
) error {
	logger := log.FromContext(ctx)
	deployment, err := r.getTargetDeployment(ctx, identity)
	if err != nil {
		return err
	}
	if deployment == nil {
		return nil
	}
	if err := r.Delete(ctx, deployment); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	logger.Info("Deleted target Deployment", "deployment", deployment.Name)
	return nil
}

// SetCondition upserts a condition and updates lastTransitionTime only when status changes.
func SetCondition(
	conditions *[]metav1.Condition,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}
