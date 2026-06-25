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
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1alpha1 "github.com/Bobbins228/Agenix/agenix-operator/api/v1alpha1"
	"github.com/Bobbins228/Agenix/agenix-operator/internal/ca"
)

var _ = Describe("AgentIdentity Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceNamespace = "default"
			testApp           = "test"
			testLabelKey      = "app"
			testImage         = "busybox"
			testTrustDomain   = "example.org"
			testTTL           = "24h"
			foundName         = "test-found"
			foundDeployment   = "found-deployment"
			missingName       = "test-missing"
			missingDeployment = "does-not-exist"
			recreateName      = "test-recreate"
			idempotentName    = "test-idempotent"
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
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      foundName,
					Namespace: resourceNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      foundName,
				Namespace: resourceNamespace,
			}, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Provisioned"))
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
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      recreateName,
					Namespace: resourceNamespace,
				},
			})
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
			firstSerial := updated.Status.Certificate.SerialNumber

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      idempotentName,
					Namespace: resourceNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			updated2 := &agentv1alpha1.AgentIdentity{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      idempotentName,
				Namespace: resourceNamespace,
			}, updated2)).To(Succeed())
			secondSerial := updated2.Status.Certificate.SerialNumber

			Expect(secondSerial).To(Equal(firstSerial))
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
					Name:      "test-owner",
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

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-owner",
					Namespace: resourceNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "test-owner-tls",
				Namespace: resourceNamespace,
			}, secret)).To(Succeed())

			Expect(secret.OwnerReferences).To(HaveLen(1))
			Expect(secret.OwnerReferences[0].Name).To(Equal("test-owner"))
		})
	})
})
