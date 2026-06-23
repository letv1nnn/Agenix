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
			foundName         = "test-found"
			foundDeployment   = "found-deployment"
			missingName       = "test-missing"
			missingDeployment = "does-not-exist"
		)

		ctx := context.Background()

		It("should set Pending when Deployment exists", func() {
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      foundDeployment,
					Namespace: resourceNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": testApp},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{"app": testApp},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: testApp, Image: "busybox"},
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
			Expect(updated.Status.Phase).To(Equal("Pending"))
			condition := meta.FindStatusCondition(updated.Status.Conditions, "TargetFound")
			Expect(condition).NotTo(BeNil())
			Expect(condition.Status).To(Equal(metav1.ConditionTrue))
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
	})
})
