package main

import (
	"encoding/json"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestExtractEndpointInfoNil(t *testing.T) {
	monitor := &PolicyViolationMonitor{}
	info := monitor.extractEndpointInfo(nil, "")

	if info.Namespace != "" {
		t.Error("Expected empty namespace for nil endpoint")
	}
}

func TestExtractEndpointInfoNilWithIP(t *testing.T) {
	monitor := &PolicyViolationMonitor{}
	info := monitor.extractEndpointInfo(nil, "10.0.0.5")

	if info.IP != "10.0.0.5" {
		t.Errorf("Expected IP 10.0.0.5, got %s", info.IP)
	}
}

func TestExtractEndpointInfoWithData(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	endpoint := &flowpb.Endpoint{
		Namespace: "kube-system",
		PodName:   "cilium-agent-xyz",
		ID:        12345,
		Labels:    []string{"app=cilium", "k8s:app=cilium"},
	}

	info := monitor.extractEndpointInfo(endpoint, "10.0.1.15")

	if info.Namespace != "kube-system" {
		t.Errorf("Expected kube-system, got %s", info.Namespace)
	}
	if info.PodName != "cilium-agent-xyz" {
		t.Errorf("Expected cilium-agent-xyz, got %s", info.PodName)
	}
	if info.ID != 12345 {
		t.Errorf("Expected 12345, got %d", info.ID)
	}
	if len(info.Labels) != 2 {
		t.Errorf("Expected 2 labels, got %d", len(info.Labels))
	}
	if info.IP != "10.0.1.15" {
		t.Errorf("Expected IP 10.0.1.15, got %s", info.IP)
	}
}

func TestExtractProtocolInfoTCP(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      8080,
					DestinationPort: 80,
				},
			},
		},
	}

	info := monitor.extractProtocolInfo(flow)

	if info.Type != "TCP" {
		t.Errorf("Expected TCP, got %s", info.Type)
	}
	if info.SourcePort != 8080 {
		t.Errorf("Expected 8080, got %d", info.SourcePort)
	}
	if info.DestinationPort != 80 {
		t.Errorf("Expected 80, got %d", info.DestinationPort)
	}
}

func TestExtractProtocolInfoUDP(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_UDP{
				UDP: &flowpb.UDP{
					SourcePort:      53,
					DestinationPort: 1053,
				},
			},
		},
	}

	info := monitor.extractProtocolInfo(flow)

	if info.Type != "UDP" {
		t.Errorf("Expected UDP, got %s", info.Type)
	}
	if info.SourcePort != 53 {
		t.Errorf("Expected 53, got %d", info.SourcePort)
	}
}

func TestExtractProtocolInfoICMPv4(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_ICMPv4{
				ICMPv4: &flowpb.ICMPv4{
					Type: 8, // Echo request
					Code: 0,
				},
			},
		},
	}

	info := monitor.extractProtocolInfo(flow)

	if info.Type != "ICMPv4" {
		t.Errorf("Expected ICMPv4, got %s", info.Type)
	}
	if info.ICMPType != 8 {
		t.Errorf("Expected 8, got %d", info.ICMPType)
	}
}

func TestExtractProtocolInfoNil(t *testing.T) {
	monitor := &PolicyViolationMonitor{}
	flow := &flowpb.Flow{L4: nil}

	info := monitor.extractProtocolInfo(flow)

	if info.Type != "unknown" {
		t.Errorf("Expected unknown, got %s", info.Type)
	}
}

func TestGetPolicyInfo(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	// Test with policy match type
	flow := &flowpb.Flow{
		PolicyMatchType: 2, // L3_L4
	}

	info := monitor.getPolicyInfo(flow)
	expected := "Policy match type: L3_L4"

	if info != expected {
		t.Errorf("Expected '%s', got '%s'", expected, info)
	}
}

func TestGetPolicyInfoDropReason(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		PolicyMatchType: 0,
		DropReasonDesc:  flowpb.DropReason_POLICY_DENIED,
	}

	info := monitor.getPolicyInfo(flow)

	if info == "" {
		t.Error("Expected non-empty policy info for POLICY_DENIED")
	}
	if info == "Network policy denied" {
		t.Error("Should not fall back to default message when drop reason is available")
	}
}

func TestExtractFlowDetails(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		Ethernet: &flowpb.Ethernet{
			Source:      "aa:bb:cc:dd:ee:ff",
			Destination: "11:22:33:44:55:66",
		},
		IP: &flowpb.IP{
			Source:      "10.0.0.1",
			Destination: "10.0.0.2",
		},
	}

	details := monitor.extractFlowDetails(flow)

	if details.EthernetSource != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Expected aa:bb:cc:dd:ee:ff, got %s", details.EthernetSource)
	}
	if details.IPSource != "10.0.0.1" {
		t.Errorf("Expected 10.0.0.1, got %s", details.IPSource)
	}
}

func TestPolicyMatchTypeToString(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{PolicyMatchNone, "NONE"},
		{PolicyMatchL3Only, "L3_ONLY"},
		{PolicyMatchL3L4, "L3_L4"},
		{PolicyMatchL4Only, "L4_ONLY"},
		{PolicyMatchAll, "ALL"},
		{PolicyMatchProtoOnly, "PROTO_ONLY"},
		{99, "UNKNOWN(99)"},
	}

	for _, test := range tests {
		result := policyMatchTypeToString(test.input)
		if result != test.expected {
			t.Errorf("policyMatchTypeToString(%d): expected %s, got %s", test.input, test.expected, result)
		}
	}
}

func TestExtractDeniedByPoliciesEmpty(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{}

	policies := monitor.extractDeniedByPolicies(flow)

	if policies != nil {
		t.Errorf("Expected nil for empty policies, got %v", policies)
	}
}

func TestExtractDeniedByPoliciesWithEgress(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		EgressDeniedBy: []*flowpb.Policy{
			{
				Name:      "test-policy",
				Namespace: "test-namespace",
				Labels:    []string{"app=test"},
			},
		},
	}

	policies := monitor.extractDeniedByPolicies(flow)

	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got '%s'", policies[0].Name)
	}
	if policies[0].Namespace != "test-namespace" {
		t.Errorf("Expected namespace 'test-namespace', got '%s'", policies[0].Namespace)
	}
}

func TestExtractDeniedByPoliciesWithIngress(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		IngressDeniedBy: []*flowpb.Policy{
			{
				Name:      "ingress-policy",
				Namespace: "secure-namespace",
			},
		},
	}

	policies := monitor.extractDeniedByPolicies(flow)

	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "ingress-policy" {
		t.Errorf("Expected policy name 'ingress-policy', got '%s'", policies[0].Name)
	}
}

func TestExtractDeniedByPoliciesCombined(t *testing.T) {
	monitor := &PolicyViolationMonitor{}

	flow := &flowpb.Flow{
		EgressDeniedBy: []*flowpb.Policy{
			{
				Name:      "egress-policy",
				Namespace: "ns1",
			},
		},
		IngressDeniedBy: []*flowpb.Policy{
			{
				Name:      "ingress-policy",
				Namespace: "ns2",
			},
		},
	}

	policies := monitor.extractDeniedByPolicies(flow)

	if len(policies) != 2 {
		t.Fatalf("Expected 2 policies, got %d", len(policies))
	}
}

func TestPolicyViolationJSONSerialization(t *testing.T) {
	violation := PolicyViolation{
		Timestamp:        "2024-01-01T12:00:00Z",
		EventType:        "POLICY_VERDICT",
		NodeName:         "worker-1",
		Verdict:          "DROPPED",
		DropReason:       "POLICY_DENIED",
		PolicyInfo:       "Policy match type: L3_L4",
		TrafficDirection: "EGRESS",
		PolicyMatchType:  "L3_L4",
		Source: EndpointInfo{
			Namespace: "default",
			PodName:   "client-pod",
			IP:        "10.0.1.10",
		},
		Destination: EndpointInfo{
			Namespace: "secure",
			PodName:   "server-pod",
			IP:        "10.0.2.20",
		},
		Protocol: ProtocolInfo{
			Type:            "TCP",
			DestinationPort: 443,
		},
		DeniedBy: []PolicyReference{
			{
				Name:      "deny-all-egress",
				Namespace: "default",
			},
		},
	}

	jsonData, err := json.Marshal(violation)
	if err != nil {
		t.Fatalf("Failed to marshal PolicyViolation: %v", err)
	}

	// Verify we can unmarshal it back
	var unmarshaled PolicyViolation
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal PolicyViolation: %v", err)
	}

	if unmarshaled.NodeName != "worker-1" {
		t.Errorf("Expected worker-1, got %s", unmarshaled.NodeName)
	}
	if unmarshaled.Source.IP != "10.0.1.10" {
		t.Errorf("Expected source IP 10.0.1.10, got %s", unmarshaled.Source.IP)
	}
	if unmarshaled.Destination.IP != "10.0.2.20" {
		t.Errorf("Expected destination IP 10.0.2.20, got %s", unmarshaled.Destination.IP)
	}
	if unmarshaled.TrafficDirection != "EGRESS" {
		t.Errorf("Expected traffic direction EGRESS, got %s", unmarshaled.TrafficDirection)
	}
	if unmarshaled.PolicyMatchType != "L3_L4" {
		t.Errorf("Expected policy match type L3_L4, got %s", unmarshaled.PolicyMatchType)
	}
	if len(unmarshaled.DeniedBy) != 1 {
		t.Fatalf("Expected 1 denied_by policy, got %d", len(unmarshaled.DeniedBy))
	}
	if unmarshaled.DeniedBy[0].Name != "deny-all-egress" {
		t.Errorf("Expected denied_by policy name 'deny-all-egress', got '%s'", unmarshaled.DeniedBy[0].Name)
	}
}

func TestPolicyViolationJSONOmitsEmptyFields(t *testing.T) {
	violation := PolicyViolation{
		Timestamp:        "2024-01-01T12:00:00Z",
		EventType:        "POLICY_VERDICT",
		NodeName:         "worker-1",
		Verdict:          "DROPPED",
		TrafficDirection: "INGRESS",
		Source:           EndpointInfo{},
		Destination:      EndpointInfo{},
		Protocol:         ProtocolInfo{Type: "TCP"},
		// DeniedBy is nil - should be omitted
		// PolicyMatchType is empty - should be omitted
	}

	jsonData, err := json.Marshal(violation)
	if err != nil {
		t.Fatalf("Failed to marshal PolicyViolation: %v", err)
	}

	jsonStr := string(jsonData)

	// Check that empty fields are omitted
	if contains(jsonStr, "denied_by") {
		t.Error("Expected denied_by to be omitted from JSON when nil")
	}
	if contains(jsonStr, "policy_match_type") {
		t.Error("Expected policy_match_type to be omitted from JSON when empty")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}