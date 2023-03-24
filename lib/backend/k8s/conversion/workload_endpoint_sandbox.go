package conversion

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	linuxInterfaceNameMaxSize = 11
	maxLenOfPrefix            = 5

	runtimeRequestTimeout  = time.Minute * 2
	defaultRuntimeEndpoint = "unix:///var/run/dockershim.sock"

	KubernetesPodNameLabel      = "io.kubernetes.pod.name"
	KubernetesPodNamespaceLabel = "io.kubernetes.pod.namespace"
	LabelKeySaiShangIPAMIPSet   = "alcor.io/saishang-ipam.ipset"
)

type sandboxWorkloadEndpointConverter struct {
	kruntimeapi.RuntimeServiceClient
}

func newSandboxWorkloadEndpointConverter() *sandboxWorkloadEndpointConverter {
	// dfy: 日志排错
	log.Warnf("This field call dfy-func newSandboxWorkloadEndpointConverter")
	filePath := "/var/log/dfy-error-log.txt"
	file, _ := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	writer := bufio.NewWriter(file)
	writer.WriteString("starting newSandboxWorkloadEndpointConverter ...... \n")
	writer.Flush()
	defer file.Close()

	c := &sandboxWorkloadEndpointConverter{}
	var err error

	runtimeEndpoint := os.Getenv("FELIX_RUNTIMEENDPOINT")
	if runtimeEndpoint == "" {
		runtimeEndpoint = defaultRuntimeEndpoint
	}

	c.RuntimeServiceClient, err = newEndpointService(runtimeEndpoint, runtimeRequestTimeout)
	if err != nil {
		log.WithError(err).Panicf("initial sandboxWorkloadEndpointConverter failed")
		writer.WriteString("newEndpointService error \n")
		writer.Flush()
		return nil
	}
	// dfy: 日志排错
	log.Warnf("This field call dfy-func newSandboxWorkloadEndpointConverter Ending")
	writer.WriteString("ending newSandboxWorkloadEndpointConverter ...... \n")
	writer.Flush()

	return c
}

// VethNameForWorkload returns a deterministic veth name
// for the given Kubernetes workload (WEP) name and namespace.
func (wc sandboxWorkloadEndpointConverter) VethNameForWorkload(namespace, podname string) string {
	// dfy: 日志排错
	log.Warnf("This field call dfy-func VethNameForWorkload")
	filePath := "/var/log/dfy-log.txt"
	file, _ := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	writer := bufio.NewWriter(file)
	writer.WriteString("starting VethNameForWorkload ...... ")
	writer.Flush()
	defer file.Close()

	listReq := &kruntimeapi.ListPodSandboxRequest{
		Filter: &kruntimeapi.PodSandboxFilter{
			LabelSelector: map[string]string{KubernetesPodNamespaceLabel: namespace, KubernetesPodNameLabel: podname},
		},
	}
	ctx, cancel := getContextWithTimeout(runtimeRequestTimeout)
	defer cancel()
	podSandboxList, err := wc.ListPodSandbox(ctx, listReq)
	if err != nil {
		log.WithField("label", listReq.Filter.String()).Errorf("list podsandbox by filter failed")
		return ""
	}
	if len(podSandboxList.Items) == 0 {
		log.WithField("label", listReq.Filter.String()).Errorf("list podsandbox by filter empty")
		return ""
	}
	sandboxID := podSandboxList.Items[0].Id

	// dfy-log
	str := fmt.Sprintf("%s%s\n", "sandboxID:", sandboxID)
	writer.WriteString(str)
	str = fmt.Sprintf("%s%s\n", "judge whether has ipsetLable:", podSandboxList.Items[0].Labels[LabelKeySaiShangIPAMIPSet])
	writer.WriteString(str)
	writer.Flush()

	prefix := os.Getenv("FELIX_INTERFACEPREFIX")
	if podSandboxList.Items[0].Labels[LabelKeySaiShangIPAMIPSet] != "" {
		// dfy: saishang 逻辑
		prefix = "isi"
	} else {
		// dfy: 原始 calico 逻辑
		// A SHA1 is always 20 bytes long, and so is sufficient for generating the
		// veth name and mac addr.
		h := sha1.New()
		h.Write([]byte(fmt.Sprintf("%s.%s", namespace, podname)))
		prefix := os.Getenv("FELIX_INTERFACEPREFIX")
		if prefix == "" {
			// Prefix is not set. Default to "cali"
			prefix = "cali"
		} else {
			// Prefix is set - use the first value in the list.
			splits := strings.Split(prefix, ",")
			prefix = splits[0]
		}
		log.WithField("prefix", prefix).Warnf("Using prefix to create a WorkloadEndpoint veth name")
		// dfy: 日志排错
		log.Warnf("This field call dfy-func VethNameForWorkload cali-Ending")
		str = fmt.Sprintf("%s%s\n", "current prefix: ", prefix)
		writer.WriteString(str)
		writer.Flush()

		return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(h.Sum(nil))[:11])
	}
	log.WithField("prefix", prefix).Warnf("Using prefix to create a WorkloadEndpoint veth name")
	result := fmt.Sprintf("%s%s", prefix, sandboxID[:linuxInterfaceNameMaxSize-len(prefix)])
	log.WithField("vethname", result).Warnf("Using WorkloadEndpoint veth name")
	// dfy: 日志排错
	log.Warnf("This field call dfy-func VethNameForWorkload isi-Ending")
	str = fmt.Sprintf("%s%s\n", "current prefix: ", prefix)
	writer.WriteString(str)
	writer.Flush()

	return result
}

func (wc sandboxWorkloadEndpointConverter) PodToWorkloadEndpoints(pod *kapiv1.Pod) ([]*model.KVPair, error) {
	log.Warnf("dfy-func PodToWorkloadEndpoints starting --> podToDefaultWorkloadEndpoint")
	wep, err := wc.podToDefaultWorkloadEndpoint(pod)
	if err != nil {
		return nil, err
	}

	return []*model.KVPair{wep}, nil
}

// PodToWorkloadEndpoint converts a Pod to a WorkloadEndpoint.  It assumes the calling code
// has verified that the provided Pod is valid to convert to a WorkloadEndpoint.
// PodToWorkloadEndpoint requires a Pods Name and Node Name to be populated. It will
// fail to convert from a Pod to WorkloadEndpoint otherwise.
func (wc sandboxWorkloadEndpointConverter) podToDefaultWorkloadEndpoint(pod *kapiv1.Pod) (*model.KVPair, error) {
	log.Warnf("dfy-func podToDefaultWorkloadEndpoint starting -???-> VethNameForWorkload")
	log.WithField("pod", pod).Debug("Converting pod to WorkloadEndpoint")
	log.Warnf("dfy-func Converting pod to WorkloadEndpoint")
	// Get all the profiles that apply
	var profiles []string

	// Pull out the Namespace based profile off the pod name and Namespace.
	profiles = append(profiles, NamespaceProfileNamePrefix+pod.Namespace)

	// Pull out the Serviceaccount based profile off the pod SA and namespace
	if pod.Spec.ServiceAccountName != "" {
		profiles = append(profiles, serviceAccountNameToProfileName(pod.Spec.ServiceAccountName, pod.Namespace))
	}

	wepids := names.WorkloadEndpointIdentifiers{
		Node:         pod.Spec.NodeName,
		Orchestrator: apiv3.OrchestratorKubernetes,
		Endpoint:     "eth0",
		Pod:          pod.Name,
	}
	log.Warnf("dfy-func CalculateWorkloadEndpointName")
	wepName, err := wepids.CalculateWorkloadEndpointName(false)
	log.WithField("err:", err).Warnf("dfy-func CalculateWorkloadEndpointName")
	if err != nil {
		return nil, err
	}

	log.Warnf("dfy-func getPodIPs")
	podIPNets, err := getPodIPs(pod)
	log.WithField("err:", err).Warnf("dfy-func getPodIPs")
	if err != nil {
		// IP address was present but malformed in some way, handle as an explicit failure.
		return nil, err
	}

	log.Warnf("dfy-func IsFinished Pod")
	if IsFinished(pod) {
		// Pod is finished but not yet deleted.  In this state the IP will have been freed and returned to the pool
		// so we need to make sure we don't let the caller believe it still belongs to this endpoint.
		// Pods with no IPs will get filtered out before they get to Felix in the watcher syncer cache layer.
		// We can't pretend the workload endpoint is deleted _here_ because that would confuse users of the
		// native v3 Watch() API.
		log.Debug("Pod is in a 'finished' state so no longer owns its IP(s).")
		podIPNets = nil
	}
	log.Warnf("dfy-func IsFinished Pod ending")

	ipNets := []string{}
	for _, ipNet := range podIPNets {
		ipNets = append(ipNets, ipNet.String())
	}

	log.Warnf("dfy-func VethNameForWorkload starting")
	// Generate the interface name based on workload.  This must match
	// the host-side veth configured by the CNI plugin.
	interfaceName := wc.VethNameForWorkload(pod.Namespace, pod.Name)
	if interfaceName == "" {
		return nil, fmt.Errorf("convert an empty interface name from pod: %s/%s", pod.Namespace, pod.Name)
	}
	log.Warnf("dfy-func VethNameForWorkload ending")

	// Build the labels map.  Start with the pod labels, and append two additional labels for
	// namespace and orchestrator matches.
	labels := pod.Labels
	if labels == nil {
		labels = make(map[string]string, 2)
	}
	labels[apiv3.LabelNamespace] = pod.Namespace
	labels[apiv3.LabelOrchestrator] = apiv3.OrchestratorKubernetes

	if pod.Spec.ServiceAccountName != "" {
		labels[apiv3.LabelServiceAccount] = pod.Spec.ServiceAccountName
	}

	// Pull out floating IP annotation
	var floatingIPs []apiv3.IPNAT
	if annotation, ok := pod.Annotations["cni.projectcalico.org/floatingIPs"]; ok && len(podIPNets) > 0 {

		// Parse Annotation data
		var ips []string
		err := json.Unmarshal([]byte(annotation), &ips)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s' as JSON: %s", annotation, err)
		}

		// Get IPv4 and IPv6 targets for NAT
		var podnetV4, podnetV6 *cnet.IPNet
		for _, ipNet := range podIPNets {
			if ipNet.IP.To4() != nil {
				podnetV4 = ipNet
				netmask, _ := podnetV4.Mask.Size()
				if netmask != 32 {
					return nil, fmt.Errorf("PodIP %v is not a valid IPv4: Mask size is %d, not 32", ipNet, netmask)
				}
			} else {
				podnetV6 = ipNet
				netmask, _ := podnetV6.Mask.Size()
				if netmask != 128 {
					return nil, fmt.Errorf("PodIP %v is not a valid IPv6: Mask size is %d, not 128", ipNet, netmask)
				}
			}
		}

		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				if podnetV6 != nil {
					floatingIPs = append(floatingIPs, apiv3.IPNAT{
						InternalIP: podnetV6.IP.String(),
						ExternalIP: ip,
					})
				}
			} else {
				if podnetV4 != nil {
					floatingIPs = append(floatingIPs, apiv3.IPNAT{
						InternalIP: podnetV4.IP.String(),
						ExternalIP: ip,
					})
				}
			}
		}
	}

	// Map any named ports through.
	var endpointPorts []apiv3.EndpointPort
	for _, container := range pod.Spec.Containers {
		for _, containerPort := range container.Ports {
			if containerPort.Name != "" && containerPort.ContainerPort != 0 {
				var modelProto numorstring.Protocol
				switch containerPort.Protocol {
				case kapiv1.ProtocolUDP:
					modelProto = numorstring.ProtocolFromString("udp")
				case kapiv1.ProtocolTCP, kapiv1.Protocol("") /* K8s default is TCP. */ :
					modelProto = numorstring.ProtocolFromString("tcp")
				default:
					log.WithFields(log.Fields{
						"protocol": containerPort.Protocol,
						"pod":      pod,
						"port":     containerPort,
					}).Debug("Ignoring named port with unknown protocol")
					continue
				}

				endpointPorts = append(endpointPorts, apiv3.EndpointPort{
					Name:     containerPort.Name,
					Protocol: modelProto,
					Port:     uint16(containerPort.ContainerPort),
				})
			}
		}
	}

	// Create the workload endpoint.
	wep := apiv3.NewWorkloadEndpoint()
	wep.ObjectMeta = metav1.ObjectMeta{
		Name:              wepName,
		Namespace:         pod.Namespace,
		CreationTimestamp: pod.CreationTimestamp,
		UID:               pod.UID,
		Labels:            labels,
		GenerateName:      pod.GenerateName,
	}
	wep.Spec = apiv3.WorkloadEndpointSpec{
		Orchestrator:  "k8s",
		Node:          pod.Spec.NodeName,
		Pod:           pod.Name,
		Endpoint:      "eth0",
		InterfaceName: interfaceName,
		Profiles:      profiles,
		IPNetworks:    ipNets,
		Ports:         endpointPorts,
		IPNATs:        floatingIPs,
	}

	// Embed the workload endpoint into a KVPair.
	kvp := model.KVPair{
		Key: model.ResourceKey{
			Name:      wepName,
			Namespace: pod.Namespace,
			Kind:      apiv3.KindWorkloadEndpoint,
		},
		Value:    wep,
		Revision: pod.ResourceVersion,
	}
	return &kvp, nil
}
