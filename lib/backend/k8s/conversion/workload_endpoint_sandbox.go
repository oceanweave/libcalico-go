// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conversion

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeletapi "k8s.io/cri-api/pkg/apis"
	kruntimeapi "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	kubeletremote "k8s.io/kubernetes/pkg/kubelet/remote"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	linuxInterfaceNameMaxSize = 15

	runtimeRequestTimeout = time.Minute * 2
	runtimeEndpoint       = "unix:///var/run/dockershim.sock"

	KubernetesPodNameLabel      = "io.kubernetes.pod.name"
	KubernetesPodNamespaceLabel = "io.kubernetes.pod.namespace"
)

type sandboxWorkloadEndpointConverter struct {
	kubeletapi.RuntimeService // dfy: 封装此接口作用，是为了获取容器相关信息
}

func newSandboxWorkloadEndpointConverter() *sandboxWorkloadEndpointConverter {
	c := &sandboxWorkloadEndpointConverter{}
	var err error
	c.RuntimeService, err = kubeletremote.NewRemoteRuntimeService(runtimeEndpoint, runtimeRequestTimeout)
	if err != nil {
		log.WithError(err).Panicf("initial sandboxWorkloadEndpointConverter failed")
		return nil
	}
	return c
}

// VethNameForWorkload returns a deterministic veth name
// for the given Kubernetes workload (WEP) name and namespace.
func (wc sandboxWorkloadEndpointConverter) VethNameForWorkload(namespace, podname string) string {
	filter := &kruntimeapi.PodSandboxFilter{
		LabelSelector: map[string]string{KubernetesPodNamespaceLabel: namespace, KubernetesPodNameLabel: podname},
	}
	// dfy: 获取指定 ns 下指定 Pod 对应的 所有容器？
	podSandboxList, err := wc.ListPodSandbox(filter)
	if err != nil {
		log.WithField("label", filter.String()).Errorf("list podsandbox by filter failed")
		return ""
	}
	if len(podSandboxList) == 0 {
		log.WithField("label", filter.String()).Errorf("list podsandbox by filter empty")
		return ""
	}
	// dfy: 获取该 Pod 的第一个容器 ID
	sandboxID := podSandboxList[0].Id
	// dfy: 获取环境变量，判断是否有指定 veth pair 前缀，若没有就默认采用 cali 前缀
	prefix := os.Getenv("FELIX_INTERFACEPREFIX")
	if prefix == "" {
		// Prefix is not set. Default to "cali"
		prefix = "cali"
	} else {
		// Prefix is set - use the first value in the list.
		splits := strings.Split(prefix, ",")
		prefix = splits[0]
	}
	log.WithField("prefix", prefix).Debugf("Using prefix to create a WorkloadEndpoint veth name")
	// dfy: 此处指定了 veth-pair 前缀为 15 个字符长度
	result := fmt.Sprintf("%s%s", prefix, sandboxID[:linuxInterfaceNameMaxSize-len(prefix)])
	log.WithField("vethname", result).Debugf("Using WorkloadEndpoint veth name")
	return result
}

func (wc sandboxWorkloadEndpointConverter) PodToWorkloadEndpoints(pod *kapiv1.Pod) ([]*model.KVPair, error) {
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
	log.WithField("pod", pod).Debug("Converting pod to WorkloadEndpoint")
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
	wepName, err := wepids.CalculateWorkloadEndpointName(false)
	if err != nil {
		return nil, err
	}

	podIPNets, err := getPodIPs(pod)
	if err != nil {
		// IP address was present but malformed in some way, handle as an explicit failure.
		return nil, err
	}

	if IsFinished(pod) {
		// Pod is finished but not yet deleted.  In this state the IP will have been freed and returned to the pool
		// so we need to make sure we don't let the caller believe it still belongs to this endpoint.
		// Pods with no IPs will get filtered out before they get to Felix in the watcher syncer cache layer.
		// We can't pretend the workload endpoint is deleted _here_ because that would confuse users of the
		// native v3 Watch() API.
		log.Debug("Pod is in a 'finished' state so no longer owns its IP(s).")
		podIPNets = nil
	}

	ipNets := []string{}
	for _, ipNet := range podIPNets {
		ipNets = append(ipNets, ipNet.String())
	}

	// Generate the interface name based on workload.  This must match
	// the host-side veth configured by the CNI plugin.
	// dfy: 此处要与建立的 host 端 veth-pair 名称对应
	interfaceName := wc.VethNameForWorkload(pod.Namespace, pod.Name)
	if interfaceName == "" {
		return nil, fmt.Errorf("convert an empty interface name from pod: %s/%s", pod.Namespace, pod.Name)
	}

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