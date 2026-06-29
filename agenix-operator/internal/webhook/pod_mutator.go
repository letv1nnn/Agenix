package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentv1alpha1 "github.com/Bobbins228/Agenix/agenix-operator/api/v1alpha1"
)

type PodMutator struct {
	Client  client.Client
	decoder admission.Decoder
}

func (m *PodMutator) InjectDecoder(d admission.Decoder) {
	m.decoder = d
}

func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	// decode pod from the admission request
	pod := &corev1.Pod{}
	err := m.decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// get deployment name
	deploymentName, ok := deploymentNameFromPod(pod)
	if !ok {
		return admission.Allowed("pod is not owned by a Deployment ReplicaSet")
	}

	// use deploymentName to find matching AgentIdentity, if exists
	agentIdentity, found, err := m.findAgentIdentity(ctx, req.Namespace, deploymentName)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if !found {
		return admission.Allowed("no matching AgentIdentity")
	}

	if agentIdentity.Status.AgentID == "" {
		return admission.Allowed("AgentIdentity not yet reconciled")
	}

	if hasAgentIdentityVolume(pod) {
		return admission.Allowed("agent-identity volume already present")
	}

	mutatePod(pod, agentIdentity)

	// return an admission response with JSON patch
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func deploymentNameFromPod(pod *corev1.Pod) (string, bool) { // takes in decoded pod, outputs the deploymentName and whether match was found
	for _, ref := range pod.OwnerReferences { // for every owner ref in pod
		if ref.Controller == nil || !*ref.Controller { // if theres no controller flag OR if not main controller owner
			continue
		}

		if ref.Kind != "ReplicaSet" { // if it doesnt have a kind of ReplicaSet
			continue
		} // because if pod is managed by deployment then it is owned by replica set

		hash := pod.Labels["pod-template-hash"] // replica set name includes this hash
		// ref.Name = replica set name = <deployment-name>-<hash>

		if hash == "" { // if label is missing
			continue
		}

		suffix := "-" + hash // '-<hash>'

		name, _ := strings.CutSuffix(ref.Name, suffix) // deployment name = ReplicaSet name - '-<hash>'
		if name != "" {
			return name, true // name, name was found
		}

	}
	return "", false // empty name, no match was found
}

func (m *PodMutator) findAgentIdentity(ctx context.Context, namespace, deploymentName string) (*agentv1alpha1.AgentIdentity, bool, error) {
	var list agentv1alpha1.AgentIdentityList // k8s list type: Items []AgentIdentity

	if err := m.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil { // if list call failed
		return nil, false, err
	}

	for i := range list.Items { // for every AgentIdentity in the namespace
		ai := &list.Items[i]                          // ai = pointer to slice item
		if ai.Spec.TargetRef.Name == deploymentName { // if the deployment name from this item == deploymentName
			return ai, true, nil // return identity, found, nil error
		}
	}
	return nil, false, nil // checked list, not found, nil error
}

const vName = "agent-identity"

func hasAgentIdentityVolume(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == vName {
			return true
		}
	}
	return false
}

func mutatePod(pod *corev1.Pod, ai *agentv1alpha1.AgentIdentity) {
	volume := corev1.Volume{
		Name: vName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: ai.Name + "-tls",
			},
		},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, volume)

	for i := range pod.Spec.Containers { // for every container
		// add volume mount
		mount := corev1.VolumeMount{
			Name:      vName,
			MountPath: "/var/run/agenix",
			ReadOnly:  true,
		}
		pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, mount)

		// add env vars
		envVars := []corev1.EnvVar{
			{Name: "AGENIX_CERT_PATH", Value: "/var/run/agenix/tls.crt"},
			{Name: "AGENIX_KEY_PATH", Value: "/var/run/agenix/tls.key"},
			{Name: "AGENIX_CA_PATH", Value: "/var/run/agenix/ca.crt"},
			{Name: "AGENIX_AGENT_ID", Value: ai.Status.AgentID},
		}
		pod.Spec.Containers[i].Env = append(pod.Spec.Containers[i].Env, envVars...)
	}
}
