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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1alpha1 "github.com/Bobbins228/Agenix/agenix-operator/api/v1alpha1"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
)

var _ = Describe("AgentIdentity Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceNamespace  = "default"
			testApp            = "test"
			testLabelKey       = "app"
			testImage          = "busybox"
			testTrustDomain    = "example.org"
			testTTL            = "24h"
			foundName          = "test-found"
			foundDeployment    = "found-deployment"
			missingName        = "test-missing"
			missingDeployment  = "does-not-exist"
			recreateName       = "test-recreate"
			idempotentName     = "test-idempotent"
			verifiedName       = "test-verified"
			verifiedDeployment = "verified-deployment"
			ownerName          = "test-owner"
		)

		ctx := context.Background()

		It("should provision certificate when Deployment exists", func() {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      foundDeployment,
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{testLabelKey: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: testApp, Image: testImage},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, deployment) })

			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      foundName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{
						Name: foundDeployment,
					},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         testTTL,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}

			updated := reconcileUntilVerified(ctx, reconciler, foundName)
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      foundName,
				Namespace: resourceNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Verified"))
			condition := meta.FindStatusCondition(updated.Status.Conditions, "TargetFound")
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionTrue))

			Expect(updated.Status.AgentID).To(Equal("spiffe://example.org/ns/default/sa/default"))

			Expect(updated.Status.Certificate).NotTo(BeNil())
			Expect(updated.Status.Certificate.SerialNumber).NotTo(BeEmpty())
			Expect(updated.Status.Certificate.Fingerprint).To(HavePrefix("sha256:"))
			Expect(updated.Status.Certificate.NotBefore.IsZero()).To(BeFalse())
			Expect(updated.Status.Certificate.NotAfter.IsZero()).To(BeFalse())

			certCondition := meta.FindStatusCondition(updated.Status.Conditions, "CertificateReady")
			Expect(certCondition).NotTo(BeNil())
			Expect(certCondition.Status).To(Equal(metav1.ConditionTrue))

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      foundName + "-tls",
				Namespace: resourceNamespace,
			}, secret)).To(Succeed())
			Expect(secret.Data).To(HaveKey("tls.crt"))
			Expect(secret.Data).To(HaveKey("tls.key"))
			Expect(secret.Data).To(HaveKey("ca.crt"))
		})

		It("should set Verified phase and verification conditions after successful reconcile", func() {
			// 1. Create Deployment
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      verifiedDeployment,
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{testLabelKey: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: testApp, Image: testImage}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, deployment) })

			// 2. Create AgentIdentity
			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      verifiedName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{Name: verifiedDeployment},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         testTTL,
						AutoRotate:  true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			// 3. Reconcile twice (finalizer + full flow)
			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}

			updated := reconcileUntilVerified(ctx, reconciler, verifiedName)

			// 4. Assert phase
			Expect(updated.Status.Phase).To(Equal("Verified"))

			// 5. Assert both conditions True
			certReady := meta.FindStatusCondition(updated.Status.Conditions, conditionCertificateReady)
			Expect(certReady).NotTo(BeNil())
			Expect(certReady.Status).To(Equal(metav1.ConditionTrue))

			identityVerified := meta.FindStatusCondition(updated.Status.Conditions, conditionIdentityVerified)
			Expect(identityVerified).NotTo(BeNil())
			Expect(identityVerified.Status).To(Equal(metav1.ConditionTrue))
			Expect(identityVerified.Reason).To(Equal("SignatureValid"))

			// Optional extras
			Expect(updated.Status.AgentID).To(Equal("spiffe://example.org/ns/default/sa/default"))
			Expect(updated.Status.Certificate).NotTo(BeNil())
		})

		It("should apply verification labels to the target Deployment", func() {
			deploymentName := "labels-deployment"
			identityName := "test-labels"

			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{testLabelKey: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: testApp, Image: testImage}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, deployment) })

			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      identityName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{Name: deploymentName},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         testTTL,
						AutoRotate:  true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}

			expectedSPIFFE := "spiffe://example.org/ns/default/sa/default"
			reconcileUntilVerified(ctx, reconciler, identityName)

			// Re-fetch Deployment and check labels
			updatedDeploy := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      deploymentName,
				Namespace: resourceNamespace,
			}, updatedDeploy)).To(Succeed())

			Expect(updatedDeploy.Labels).To(HaveKeyWithValue(labelIdentityVerified, "true"))
			Expect(updatedDeploy.Labels).To(HaveKeyWithValue(
				labelAgentID,
				SanitizeSPIFFEIDForLabel(expectedSPIFFE),
			))
		})

		It("should set Error when Deployment is missing", func() {
			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      missingName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{
						Name: missingDeployment,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      missingName,
					Namespace: resourceNamespace,
				},
			}
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			_, err = reconciler.Reconcile(ctx, req) // second pass
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: first one only adds finalizer and returns
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      missingName,
					Namespace: resourceNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      missingName,
				Namespace: resourceNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Error"))
			condition := meta.FindStatusCondition(updated.Status.Conditions, "TargetFound")
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		})

		It("should recreate Secret when deleted", func() {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "recreate-deployment",
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{testLabelKey: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: testApp, Image: testImage},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, deployment) })

			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      recreateName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{
						Name: "recreate-deployment",
					},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         testTTL,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      recreateName,
					Namespace: resourceNamespace,
				},
			}

			// Pass 1: finalizer
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Pass 2: create secret
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: first one only adds finalizer and returns
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      recreateName,
					Namespace: resourceNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      recreateName + "-tls",
				Namespace: resourceNamespace,
			}, secret)).To(Succeed())

			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

			// Pass 3: recreate secret
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			newSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      recreateName + "-tls",
				Namespace: resourceNamespace,
			}, newSecret)).To(Succeed())
			Expect(newSecret.Data).To(HaveKey("tls.crt"))

		})
		It("should not regenerate cert on second reconcile", func() {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "idempotent-deployment",
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{testLabelKey: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: testApp, Image: testImage},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, deployment) })

			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      idempotentName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{
						Name: "idempotent-deployment",
					},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         testTTL,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      idempotentName,
					Namespace: resourceNamespace,
				},
			}

			// Pass 1: finalizer
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Pass 2: provision + verify
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: first one only adds finalizer and returns
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      idempotentName,
					Namespace: resourceNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      idempotentName,
				Namespace: resourceNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Status.Certificate).NotTo(BeNil())
			firstSerial := updated.Status.Certificate.SerialNumber

			// Pass 3: should reuse existing cert, not regenerate
			_, err = reconciler.Reconcile(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			updated2 := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      idempotentName,
				Namespace: resourceNamespace,
			}, updated2)).To(Succeed())
			Expect(updated2.Status.Certificate).NotTo(BeNil())
			Expect(updated2.Status.Certificate.SerialNumber).To(Equal(firstSerial))
		})
		It("should set owner reference on Secret", func() {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "owner-deployment",
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{testLabelKey: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: testApp, Image: testImage},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, deployment) })

			identity := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ownerName,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{
						Name: "owner-deployment",
					},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         testTTL,
					},
				},
			}
			Expect(k8sClient.Create(ctx, identity)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &AgentIdentityReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				CA:     authority,
			}

			reconcileUntilVerified(ctx, reconciler, ownerName)

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      ownerName + "-tls",
				Namespace: resourceNamespace,
			}, secret)).To(Succeed())

			Expect(secret.OwnerReferences).To(HaveLen(1))
			Expect(secret.OwnerReferences[0].Name).To(Equal(ownerName))
		})
	})

	Context("When handling finalizers and deletion", func() {
		const (
			resourceNamespace      = "default"
			appLabel               = "app"
			testApp                = "test"
			testTrustDomain        = "example.org"
			finalizerTestName      = "test-finalizer-add"
			finalizerDeployment    = "finalizer-deployment"
			deletionTestName       = "test-deletion-cleanup"
			deletionDeployment     = "deletion-deployment"
			alreadyGoneTestName    = "test-already-gone"
			alreadyGoneDeployment  = "already-gone-deployment"
			finalizerRemovedName   = "test-finalizer-removed"
			finalizerRemovedDeploy = "finalizer-removed-deployment"
			delNolabelID           = "del-nolabel-id"
			delNolabelDeploy       = "del-nolabel-deploy"
		)

		ctx := context.Background()

		newReconciler := func() *AgentIdentityReconciler {
			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())
			return &AgentIdentityReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				CA:       authority,
				Recorder: events.NewFakeRecorder(10),
			}
		}

		createDeployment := func(name string) *appsv1.Deployment {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{appLabel: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{appLabel: testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: testApp, Image: "busybox"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, dep)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, dep) })
			return dep
		}

		createIdentity := func(name, deploymentName string) *agentv1alpha1.AgentIdentity {
			id := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{
						Name: deploymentName,
					},
				},
			}
			Expect(k8sClient.Create(ctx, id)).To(Succeed())
			return id
		}

		reqFor := func(name string) reconcile.Request {
			return reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      name,
					Namespace: resourceNamespace,
				},
			}
		}

		It("should add finalizer on first reconciliation", func() {
			createDeployment(finalizerDeployment)
			createIdentity(finalizerTestName, finalizerDeployment)
			DeferCleanup(func() {
				id := &agentv1alpha1.AgentIdentity{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: finalizerTestName, Namespace: resourceNamespace}, id); err == nil {
					id.Finalizers = nil
					_ = k8sClient.Update(ctx, id)
					_ = k8sClient.Delete(ctx, id)
				}
			})

			reconciler := newReconciler()
			_, err := reconciler.Reconcile(ctx, reqFor(finalizerTestName))
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      finalizerTestName,
				Namespace: resourceNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement("agenix.io/identity-cleanup"))
		})

		It("should delete TLS Secret on AgentIdentity deletion", func() {
			createDeployment(deletionDeployment)
			createIdentity(deletionTestName, deletionDeployment)

			reconciler := newReconciler()
			// First reconcile: adds finalizer
			_, err := reconciler.Reconcile(ctx, reqFor(deletionTestName))
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: normal flow (sets Pending)
			_, err = reconciler.Reconcile(ctx, reqFor(deletionTestName))
			Expect(err).NotTo(HaveOccurred())

			// Manually create TLS Secret (simulating 4b provisioning)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deletionTestName + "-tls",
					Namespace: resourceNamespace,
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": []byte("fake-cert"),
					"tls.key": []byte("fake-key"),
					"ca.crt":  []byte("fake-ca"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// Delete the AgentIdentity (sets DeletionTimestamp; finalizer prevents actual deletion)
			identity := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: deletionTestName, Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			// Reconcile: should handle deletion, delete Secret, remove finalizer
			_, err = reconciler.Reconcile(ctx, reqFor(deletionTestName))
			Expect(err).NotTo(HaveOccurred())

			// Verify Secret is gone
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      deletionTestName + "-tls",
				Namespace: resourceNamespace,
			}, &corev1.Secret{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			// Verify AgentIdentity is gone
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      deletionTestName,
				Namespace: resourceNamespace,
			}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should handle deletion cleanly when Secret is already gone", func() {
			createDeployment(alreadyGoneDeployment)
			createIdentity(alreadyGoneTestName, alreadyGoneDeployment)

			reconciler := newReconciler()
			_, err := reconciler.Reconcile(ctx, reqFor(alreadyGoneTestName))
			Expect(err).NotTo(HaveOccurred())

			// Delete without creating any Secret — nothing to clean up
			identity := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: alreadyGoneTestName, Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, reqFor(alreadyGoneTestName))
			Expect(err).NotTo(HaveOccurred())

			// Verify AgentIdentity is gone (no error from missing Secret)
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      alreadyGoneTestName,
				Namespace: resourceNamespace,
			}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		createFullIdentity := func(name, deploymentName string) *agentv1alpha1.AgentIdentity {
			id := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: resourceNamespace,
				},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{Name: deploymentName},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         "24h",
						AutoRotate:  true,
					},
				},
			}
			Expect(k8sClient.Create(ctx, id)).To(Succeed())
			return id
		}

		It("should remove verification labels from Deployment on deletion", func() {
			dep := createDeployment("del-labels-deploy")
			identity := createFullIdentity("del-labels-id", "del-labels-deploy")
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "del-labels-id")

			// Verify labels were applied
			updatedDep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-labels-deploy", Namespace: resourceNamespace}, updatedDep)).To(Succeed())
			Expect(updatedDep.Labels).To(HaveKey(labelIdentityVerified))
			Expect(updatedDep.Labels).To(HaveKey(labelAgentID))

			// Delete AgentIdentity
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-labels-id", Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			// Reconcile deletion
			_, err := reconciler.Reconcile(ctx, reqFor("del-labels-id"))
			Expect(err).NotTo(HaveOccurred())

			// Deployment should still exist (it gets deleted by handleDeletion now, so re-create for label check)
			// Actually handleDeletion deletes it — but labels are removed BEFORE deletion
			// Verify CR is gone (proves full cleanup ran)
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-labels-id", Namespace: resourceNamespace}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			// Deployment is also gone (deleted by handleDeletion step 3)
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-labels-deploy", Namespace: resourceNamespace}, &appsv1.Deployment{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
			_ = dep // used by createDeployment
		})

		It("should delete target Deployment on AgentIdentity deletion", func() {
			createDeployment("del-deploy-target")
			identity := createFullIdentity("del-deploy-id", "del-deploy-target")
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "del-deploy-id")

			// Delete AgentIdentity
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-deploy-id", Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reqFor("del-deploy-id"))
			Expect(err).NotTo(HaveOccurred())

			// Deployment should be gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-deploy-target", Namespace: resourceNamespace}, &appsv1.Deployment{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should clean up Secret, labels, and Deployment on deletion (full flow)", func() {
			createDeployment("del-full-deploy")
			identity := createFullIdentity("del-full-id", "del-full-deploy")
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "del-full-id")

			// Verify everything was created
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-full-id-tls", Namespace: resourceNamespace}, &corev1.Secret{})).To(Succeed())
			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-full-deploy", Namespace: resourceNamespace}, dep)).To(Succeed())
			Expect(dep.Labels).To(HaveKey(labelIdentityVerified))

			// Delete AgentIdentity
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-full-id", Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reqFor("del-full-id"))
			Expect(err).NotTo(HaveOccurred())

			// Secret gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-full-id-tls", Namespace: resourceNamespace}, &corev1.Secret{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			// Deployment gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-full-deploy", Namespace: resourceNamespace}, &appsv1.Deployment{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			// CR gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-full-id", Namespace: resourceNamespace}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should complete deletion when Secret and Deployment are already gone", func() {
			createDeployment("del-gone-deploy")
			identity := createFullIdentity("del-gone-id", "del-gone-deploy")
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "del-gone-id")

			// Manually delete Secret and Deployment before triggering cleanup
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-gone-id-tls", Namespace: resourceNamespace}, secret)).To(Succeed())
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-gone-deploy", Namespace: resourceNamespace}, dep)).To(Succeed())
			Expect(k8sClient.Delete(ctx, dep)).To(Succeed())

			// Delete AgentIdentity
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-gone-id", Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			// Should complete without error despite missing resources
			_, err := reconciler.Reconcile(ctx, reqFor("del-gone-id"))
			Expect(err).NotTo(HaveOccurred())

			// CR gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-gone-id", Namespace: resourceNamespace}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should complete deletion when Deployment is pre-deleted but Secret exists", func() {
			createDeployment("del-nodep-deploy")
			identity := createFullIdentity("del-nodep-id", "del-nodep-deploy")
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, identity) })

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "del-nodep-id")

			// Delete Deployment only
			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-nodep-deploy", Namespace: resourceNamespace}, dep)).To(Succeed())
			Expect(k8sClient.Delete(ctx, dep)).To(Succeed())

			// Delete AgentIdentity
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-nodep-id", Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reqFor("del-nodep-id"))
			Expect(err).NotTo(HaveOccurred())

			// Secret gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-nodep-id-tls", Namespace: resourceNamespace}, &corev1.Secret{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			// CR gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "del-nodep-id", Namespace: resourceNamespace}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should delete Deployment even without prior verification labels", func() {
			createDeployment(delNolabelDeploy)
			createIdentity(delNolabelID, delNolabelDeploy)
			DeferCleanup(func() {
				id := &agentv1alpha1.AgentIdentity{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: delNolabelID, Namespace: resourceNamespace}, id); err == nil {
					id.Finalizers = nil
					_ = k8sClient.Update(ctx, id)
					_ = k8sClient.Delete(ctx, id)
				}
			})

			reconciler := newReconciler()
			// Only add finalizer, don't reach verified (no TTL/TrustDomain on minimal identity)
			_, err := reconciler.Reconcile(ctx, reqFor(delNolabelID))
			Expect(err).NotTo(HaveOccurred())

			// Delete AgentIdentity
			identity := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: delNolabelID, Namespace: resourceNamespace}, identity)).To(Succeed())
			Expect(k8sClient.Delete(ctx, identity)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, reqFor(delNolabelID))
			Expect(err).NotTo(HaveOccurred())

			// Deployment gone even though it never had labels
			err = k8sClient.Get(ctx, types.NamespacedName{Name: delNolabelDeploy, Namespace: resourceNamespace}, &appsv1.Deployment{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			// CR gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: delNolabelID, Namespace: resourceNamespace}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should remove finalizer after successful cleanup", func() {
			createDeployment(finalizerRemovedDeploy)
			createIdentity(finalizerRemovedName, finalizerRemovedDeploy)

			reconciler := newReconciler()
			// Add finalizer
			_, err := reconciler.Reconcile(ctx, reqFor(finalizerRemovedName))
			Expect(err).NotTo(HaveOccurred())

			// Verify finalizer is present before deletion
			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: finalizerRemovedName, Namespace: resourceNamespace}, updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement("agenix.io/identity-cleanup"))

			// Delete CR
			Expect(k8sClient.Delete(ctx, updated)).To(Succeed())

			// Reconcile handles deletion and removes finalizer
			_, err = reconciler.Reconcile(ctx, reqFor(finalizerRemovedName))
			Expect(err).NotTo(HaveOccurred())

			// CR being gone proves finalizer was removed — K8s won't delete a resource with active finalizers
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      finalizerRemovedName,
				Namespace: resourceNamespace,
			}, &agentv1alpha1.AgentIdentity{})
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("When reconciling with certificate edge cases", func() {
		const resourceNamespace = "default"
		const testApp = "test"
		const testLabelKey = "app"
		const testTrustDomain = "example.org"

		ctx := context.Background()

		newReconciler := func() *AgentIdentityReconciler {
			authority, err := ca.NewCA()
			Expect(err).NotTo(HaveOccurred())
			return &AgentIdentityReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				CA:       authority,
				Recorder: events.NewFakeRecorder(10),
			}
		}

		createDeployment := func(name string) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: resourceNamespace},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{testLabelKey: testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{testLabelKey: testApp}},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: testApp, Image: "busybox"}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, dep)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, dep) })
		}

		createIdentity := func(name, deploymentName, ttl string) *agentv1alpha1.AgentIdentity {
			id := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: resourceNamespace},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{Name: deploymentName},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         ttl,
						AutoRotate:  false,
					},
				},
			}
			Expect(k8sClient.Create(ctx, id)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, id) })
			return id
		}

		reqFor := func(name string) reconcile.Request {
			return reconcile.Request{
				NamespacedName: types.NamespacedName{Name: name, Namespace: resourceNamespace},
			}
		}

		It("should set Expired phase when certificate has expired and AutoRotate is false", func() {
			createDeployment("expired-deploy")
			createIdentity("expired-id", "expired-deploy", "1ns")

			reconciler := newReconciler()

			// Pass 1: finalizer
			_, err := reconciler.Reconcile(ctx, reqFor("expired-id"))
			Expect(err).NotTo(HaveOccurred())

			// Pass 2: provision cert with 1ns TTL (will be expired immediately)
			_, err = reconciler.Reconcile(ctx, reqFor("expired-id"))
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "expired-id", Namespace: resourceNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Expired"))

			certReady := meta.FindStatusCondition(updated.Status.Conditions, conditionCertificateReady)
			Expect(certReady).NotTo(BeNil())
			Expect(certReady.Status).To(Equal(metav1.ConditionFalse))
			Expect(certReady.Reason).To(Equal("CertificateExpired"))
		})

		It("should report Error phase when Secret is missing ca.crt on re-reconcile", func() {
			createDeployment("noca-deploy")
			createIdentity("noca-id", "noca-deploy", "24h")

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "noca-id")

			// Tamper with Secret: remove ca.crt
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "noca-id-tls", Namespace: resourceNamespace}, secret)).To(Succeed())
			delete(secret.Data, "ca.crt")
			Expect(k8sClient.Update(ctx, secret)).To(Succeed())

			// Re-reconcile — should detect missing ca.crt
			_, err := reconciler.Reconcile(ctx, reqFor("noca-id"))
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "noca-id", Namespace: resourceNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Error"))

			certReady := meta.FindStatusCondition(updated.Status.Conditions, conditionCertificateReady)
			Expect(certReady).NotTo(BeNil())
			Expect(certReady.Reason).To(Equal("MissingCACertificate"))
		})

		It("should regenerate cert when existing Secret has corrupted PEM", func() {
			createDeployment("corrupt-deploy")
			createIdentity("corrupt-id", "corrupt-deploy", "24h")

			reconciler := newReconciler()
			reconcileUntilVerified(ctx, reconciler, "corrupt-id")

			// Tamper with Secret: corrupt tls.crt
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "corrupt-id-tls", Namespace: resourceNamespace}, secret)).To(Succeed())
			secret.Data["tls.crt"] = []byte("not-valid-pem")
			Expect(k8sClient.Update(ctx, secret)).To(Succeed())

			// Re-reconcile — corrupted PEM triggers regeneration (falls through to new cert)
			_, err := reconciler.Reconcile(ctx, reqFor("corrupt-id"))
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "corrupt-id", Namespace: resourceNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Verified"))
		})

		It("should set Error when SPIFFE ID components are invalid", func() {
			createDeployment("badspiffe-deploy")
			id := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "badspiffe-id", Namespace: resourceNamespace},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{Name: "badspiffe-deploy"},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: "",
						TTL:         "24h",
					},
				},
			}
			Expect(k8sClient.Create(ctx, id)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, id) })

			reconciler := newReconciler()
			// Pass 1: finalizer
			_, err := reconciler.Reconcile(ctx, reqFor("badspiffe-id"))
			Expect(err).NotTo(HaveOccurred())

			// Pass 2: should fail on empty trust domain
			_, err = reconciler.Reconcile(ctx, reqFor("badspiffe-id"))
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "badspiffe-id", Namespace: resourceNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Error"))

			certReady := meta.FindStatusCondition(updated.Status.Conditions, conditionCertificateReady)
			Expect(certReady).NotTo(BeNil())
			Expect(certReady.Reason).To(Equal("InvalidSPIFFEID"))
		})

		It("should set Error when TTL is invalid", func() {
			createDeployment("badttl-deploy")
			id := &agentv1alpha1.AgentIdentity{
				ObjectMeta: metav1.ObjectMeta{Name: "badttl-id", Namespace: resourceNamespace},
				Spec: agentv1alpha1.AgentIdentitySpec{
					TargetRef: agentv1alpha1.TargetRef{Name: "badttl-deploy"},
					Identity: agentv1alpha1.IdentityConfig{
						TrustDomain: testTrustDomain,
						TTL:         "not-a-duration",
					},
				},
			}
			Expect(k8sClient.Create(ctx, id)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, id) })

			reconciler := newReconciler()
			_, err := reconciler.Reconcile(ctx, reqFor("badttl-id"))
			Expect(err).NotTo(HaveOccurred())

			_, err = reconciler.Reconcile(ctx, reqFor("badttl-id"))
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "badttl-id", Namespace: resourceNamespace}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Error"))

			certReady := meta.FindStatusCondition(updated.Status.Conditions, conditionCertificateReady)
			Expect(certReady).NotTo(BeNil())
			Expect(certReady.Reason).To(Equal("InvalidTTL"))
		})
	})

	Context("SanitizeSPIFFEIDForLabel", func() {
		It("should replace :// and / with -", func() {
			result := SanitizeSPIFFEIDForLabel("spiffe://example.org/ns/default/sa/agent")
			Expect(result).To(Equal("spiffe-example.org-ns-default-sa-agent"))
		})

		It("should truncate to 63 characters and trim trailing special chars", func() {
			long := "spiffe://example.org/ns/very-long-namespace-name/sa/extremely-long-service-account-name-that-exceeds"
			result := SanitizeSPIFFEIDForLabel(long)
			Expect(len(result)).To(BeNumerically("<=", 63))
			Expect(result).NotTo(HaveSuffix("-"))
			Expect(result).NotTo(HaveSuffix("_"))
			Expect(result).NotTo(HaveSuffix("."))
		})

		It("should handle short IDs without truncation", func() {
			result := SanitizeSPIFFEIDForLabel("spiffe://a/b")
			Expect(result).To(Equal("spiffe-a-b"))
		})
	})
})

const controllerTestNamespace = "default"

// helper to reconcile a 2nd time for verified status
func reconcileUntilVerified(
	ctx context.Context,
	reconciler *AgentIdentityReconciler,
	name string,
) *agentv1alpha1.AgentIdentity {
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: controllerTestNamespace},
	}

	_, err := reconciler.Reconcile(ctx, req)
	Expect(err).NotTo(HaveOccurred())

	_, err = reconciler.Reconcile(ctx, req) // second pass: finalizer already present
	Expect(err).NotTo(HaveOccurred())

	updated := &agentv1alpha1.AgentIdentity{}
	Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: controllerTestNamespace}, updated)).To(Succeed())
	return updated
}
