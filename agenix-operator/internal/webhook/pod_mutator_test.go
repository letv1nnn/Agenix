package webhook

import (
	"context"
	"encoding/json"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentv1alpha1 "github.com/Bobbins228/Agenix/agenix-operator/api/v1alpha1"
)

func TestPodMutator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PodMutator Suite")
}

var _ = Describe("PodMutator", func() {
	var (
		ctx     context.Context
		mutator *PodMutator
		scheme  *runtime.Scheme
		decoder admission.Decoder
	)

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(agentv1alpha1.AddToScheme(scheme)).To(Succeed())
		decoder = admission.NewDecoder(scheme)
	})

	const testNamespace = "default"

	// Helper: creates a Pod owned by a Deployment (via ReplicaSet)
	createPodWithOwner := func(deploymentName, hash string, containerCount int) *corev1.Pod {
		containers := make([]corev1.Container, containerCount)
		for i := range containerCount {
			containers[i] = corev1.Container{
				Name:  "container-" + string(rune('0'+i)),
				Image: "nginx:latest",
			}
		}

		controller := true
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      deploymentName + "-pod-123",
				Namespace: testNamespace,
				Labels: map[string]string{
					"pod-template-hash": hash, // used to get deployment name
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       "ReplicaSet",
						Name:       deploymentName + "-" + hash,
						Controller: &controller,
					},
				},
			},
			Spec: corev1.PodSpec{
				Containers: containers,
			},
		}
	}

	// Helper: creates an admission.Request from a Pod
	createAdmissionRequest := func(pod *corev1.Pod) admission.Request {
		podBytes, err := json.Marshal(pod)
		Expect(err).NotTo(HaveOccurred())

		return admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Namespace: pod.Namespace,
				Object: runtime.RawExtension{
					Raw: podBytes,
				},
			},
		}
	}

	// Helper: creates an AgentIdentity CR
	createAgentIdentity := func(name, targetDeployment, agentID string) *agentv1alpha1.AgentIdentity {
		return &agentv1alpha1.AgentIdentity{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: testNamespace,
			},
			Spec: agentv1alpha1.AgentIdentitySpec{
				TargetRef: agentv1alpha1.TargetRef{
					Name: targetDeployment,
				},
			},
			Status: agentv1alpha1.AgentIdentityStatus{
				AgentID: agentID,
			},
		}
	}

	// TEST 1: Pod with matching AgentIdentity
	It("should mutate pod with matching AgentIdentity", func() {
		// Create an AgentIdentity that targets weather-agent deployment
		ai := createAgentIdentity("test-identity", "weather-agent",
			"spiffe://test.example.org/ns/default/sa/weather-agent")

		// Create fake client
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(ai).
			Build()

		mutator = &PodMutator{Client: fakeClient, decoder: decoder}

		// Create a pod owned by the weather-agent deployment
		pod := createPodWithOwner("weather-agent", "abc123", 1)
		req := createAdmissionRequest(pod)
		resp := mutator.Handle(ctx, req)

		Expect(resp.Allowed).To(BeTrue())
		Expect(resp.Patches).NotTo(BeEmpty())

		// Verify mutations
		expectedPod := pod.DeepCopy()
		mutatePod(expectedPod, ai)

		// Verify volume
		Expect(expectedPod.Spec.Volumes).To(HaveLen(1))
		volume := expectedPod.Spec.Volumes[0]
		Expect(volume.Name).To(Equal("agent-identity"))
		Expect(volume.VolumeSource.Secret.SecretName).To(Equal("test-identity-tls"))

		// Verify volume mount
		container := expectedPod.Spec.Containers[0]
		Expect(container.VolumeMounts).To(HaveLen(1))
		mount := container.VolumeMounts[0]
		Expect(mount.Name).To(Equal("agent-identity"))
		Expect(mount.MountPath).To(Equal("/var/run/agenix"))
		Expect(mount.ReadOnly).To(BeTrue())

		// Verify env vars
		Expect(container.Env).To(HaveLen(4))
		envMap := make(map[string]string)
		for _, env := range container.Env {
			envMap[env.Name] = env.Value
		}
		Expect(envMap["AGENIX_CERT_PATH"]).To(Equal("/var/run/agenix/tls.crt"))
		Expect(envMap["AGENIX_KEY_PATH"]).To(Equal("/var/run/agenix/tls.key"))
		Expect(envMap["AGENIX_CA_PATH"]).To(Equal("/var/run/agenix/ca.crt"))
		Expect(envMap["AGENIX_AGENT_ID"]).To(Equal("spiffe://test.example.org/ns/default/sa/weather-agent"))
	})

	// TEST 2: Pod without matching AgentIdentity
	It("should allow pod without matching AgentIdentity", func() {
		// Create an AgentIdentity for a different deployment
		ai := createAgentIdentity("other-identity", "other-deployment", "spiffe://test.example.org/other")

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ai).Build()
		mutator = &PodMutator{Client: fakeClient, decoder: decoder}

		// Create pod that doesn't match any AgentIdentity
		pod := createPodWithOwner("weather-agent", "xyz789", 1)
		req := createAdmissionRequest(pod)
		resp := mutator.Handle(ctx, req)

		Expect(resp.Allowed).To(BeTrue())
		Expect(resp.Patches).To(BeEmpty())
	})

	// TEST 3: Correct mount paths - sanity check for exact path values
	It("should use correct mount path and file paths", func() {
		ai := createAgentIdentity("path-test", "test-app", "spiffe://test/agent")
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ai).Build()
		mutator = &PodMutator{Client: fakeClient, decoder: decoder}

		pod := createPodWithOwner("test-app", "xyz", 1)
		expectedPod := pod.DeepCopy()
		mutatePod(expectedPod, ai)

		// Verify exact mount path and readOnly
		mount := expectedPod.Spec.Containers[0].VolumeMounts[0]
		Expect(mount.MountPath).To(Equal("/var/run/agenix"))
		Expect(mount.ReadOnly).To(BeTrue())

		// Verify exact env var paths
		envMap := make(map[string]string)
		for _, env := range expectedPod.Spec.Containers[0].Env {
			envMap[env.Name] = env.Value
		}
		Expect(envMap["AGENIX_CERT_PATH"]).To(Equal("/var/run/agenix/tls.crt"))
		Expect(envMap["AGENIX_KEY_PATH"]).To(Equal("/var/run/agenix/tls.key"))
		Expect(envMap["AGENIX_CA_PATH"]).To(Equal("/var/run/agenix/ca.crt"))
	})

	// TEST 4: Multiple containers
	It("should mutate all containers in a multi-container pod", func() {
		ai := createAgentIdentity("multi-identity", "multi-app", "spiffe://test.example.org/multi")

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ai).Build()
		mutator = &PodMutator{Client: fakeClient, decoder: decoder}

		// Create a pod with 2 containers
		pod := createPodWithOwner("multi-app", "def456", 2)
		req := createAdmissionRequest(pod)
		resp := mutator.Handle(ctx, req)

		Expect(resp.Allowed).To(BeTrue())
		Expect(resp.Patches).NotTo(BeEmpty())

		// Verify both containers get mutations
		expectedPod := pod.DeepCopy()
		mutatePod(expectedPod, ai)

		for i := range 2 {
			container := expectedPod.Spec.Containers[i]
			Expect(container.VolumeMounts).To(HaveLen(1))
			Expect(container.VolumeMounts[0].MountPath).To(Equal("/var/run/agenix"))
			Expect(container.Env).To(HaveLen(4))
		}
	})
})
