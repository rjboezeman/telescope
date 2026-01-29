package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

type Config struct {
	HubbleEndpoint string
	TLSEnabled     bool
	TLSSkipVerify  bool
	Namespace      string
	Since          time.Duration
	Verbose        bool
}

type PolicyViolation struct {
	Timestamp        string            `json:"timestamp"`
	EventType        string            `json:"event_type"`
	NodeName         string            `json:"node_name"`
	Source           EndpointInfo      `json:"source"`
	Destination      EndpointInfo      `json:"destination"`
	Protocol         ProtocolInfo      `json:"protocol"`
	TrafficDirection string            `json:"traffic_direction"`
	PolicyMatchType  string            `json:"policy_match_type,omitempty"`
	PolicyInfo       string            `json:"policy_info"`
	DeniedBy         []PolicyReference `json:"denied_by,omitempty"`
	DropReason       string            `json:"drop_reason,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Verdict          string            `json:"verdict"`
	FlowDetails      *FlowDetails      `json:"flow_details,omitempty"`
}

type EndpointInfo struct {
	Namespace string   `json:"namespace,omitempty"`
	PodName   string   `json:"pod_name,omitempty"`
	Labels    []string `json:"labels,omitempty"`
	ID        uint32   `json:"id,omitempty"`
	IP        string   `json:"ip,omitempty"`
}

type ProtocolInfo struct {
	Type            string `json:"type"`
	SourcePort      uint32 `json:"source_port,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
	ICMPType        uint32 `json:"icmp_type,omitempty"`
	ICMPCode        uint32 `json:"icmp_code,omitempty"`
}

type FlowDetails struct {
	EthernetSource      string `json:"ethernet_source,omitempty"`
	EthernetDestination string `json:"ethernet_destination,omitempty"`
	IPSource            string `json:"ip_source,omitempty"`
	IPDestination       string `json:"ip_destination,omitempty"`
}

type PolicyReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Labels    []string `json:"labels,omitempty"`
}

type PolicyViolationMonitor struct {
	config Config
	client observerpb.ObserverClient
	conn   *grpc.ClientConn
}

// PolicyMatchType constants from Cilium's bpf/lib/common.h
const (
	PolicyMatchNone      uint32 = 0
	PolicyMatchL3Only    uint32 = 1
	PolicyMatchL3L4      uint32 = 2
	PolicyMatchL4Only    uint32 = 3
	PolicyMatchAll       uint32 = 4
	PolicyMatchProtoOnly uint32 = 6
)

func policyMatchTypeToString(matchType uint32) string {
	switch matchType {
	case PolicyMatchNone:
		return "NONE"
	case PolicyMatchL3Only:
		return "L3_ONLY"
	case PolicyMatchL3L4:
		return "L3_L4"
	case PolicyMatchL4Only:
		return "L4_ONLY"
	case PolicyMatchAll:
		return "ALL"
	case PolicyMatchProtoOnly:
		return "PROTO_ONLY"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", matchType)
	}
}

func main() {
	config := parseFlags()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, stopping...")
		cancel()
	}()

	log.Printf("Starting Telescope - Cilium Network Policy Violation Monitor")
	log.Printf("Hubble Relay endpoint: %s", config.HubbleEndpoint)
	if config.Namespace != "" {
		log.Printf("Monitoring namespace: %s", config.Namespace)
	} else {
		log.Printf("Monitoring: ALL namespaces")
	}

	// Start monitoring with automatic reconnection
	monitorWithReconnect(ctx, config)

	log.Println("Telescope shutdown complete")
}

func parseFlags() Config {
	var config Config

	flag.StringVar(&config.HubbleEndpoint, "hubble-endpoint", "hubble-relay.kube-system.svc.cluster.local:443", "Hubble Relay endpoint")
	flag.BoolVar(&config.TLSEnabled, "tls", true, "Enable TLS connection")
	flag.BoolVar(&config.TLSSkipVerify, "tls-skip-verify", true, "Skip TLS certificate verification")
	flag.StringVar(&config.Namespace, "namespace", "", "Monitor specific namespace (empty for all namespaces - recommended)")
	flag.DurationVar(&config.Since, "since", time.Hour, "Monitor flows since this duration ago")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	return config
}

// monitorWithReconnect wraps the monitoring function with automatic reconnection logic
func monitorWithReconnect(ctx context.Context, config Config) {
	baseDelay := 5 * time.Second
	maxDelay := 5 * time.Minute
	attempt := 0

	for {
		// Check if context is cancelled before attempting connection
		if ctx.Err() != nil {
			log.Println("Context cancelled, stopping reconnection attempts")
			return
		}

		// Start monitoring (this will block until error or context cancellation)
		err := startMonitoring(ctx, config)

		// If context was cancelled, this is a clean shutdown
		if ctx.Err() != nil {
			log.Println("Shutting down as requested")
			return
		}

		// Connection failed or was interrupted
		if err != nil {
			if err == io.EOF {
				log.Println("Connection closed by Hubble Relay (EOF), will reconnect...")
			} else {
				log.Printf("Monitor failed: %v, will reconnect...", err)
			}
		}

		// Calculate exponential backoff delay
		delay := baseDelay * time.Duration(1<<uint(min(attempt, 10)))
		if delay > maxDelay {
			delay = maxDelay
		}

		log.Printf("Waiting %v before reconnecting (attempt %d)...", delay, attempt+1)
		attempt++

		// Wait before reconnecting, or exit if context is cancelled
		select {
		case <-time.After(delay):
			log.Println("Attempting to reconnect to Hubble Relay...")
		case <-ctx.Done():
			log.Println("Shutdown requested during backoff period")
			return
		}
	}
}

// startMonitoring establishes connection and monitors flows until error or context cancellation
func startMonitoring(ctx context.Context, config Config) error {
	monitor, err := NewPolicyViolationMonitor(config)
	if err != nil {
		return fmt.Errorf("failed to create monitor: %w", err)
	}
	defer monitor.Close()

	return monitor.Start(ctx)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func NewPolicyViolationMonitor(config Config) (*PolicyViolationMonitor, error) {
	var opts []grpc.DialOption

	if config.TLSEnabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(config.HubbleEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hubble Relay: %w", err)
	}

	client := observerpb.NewObserverClient(conn)

	return &PolicyViolationMonitor{
		config: config,
		client: client,
		conn:   conn,
	}, nil
}

func (m *PolicyViolationMonitor) Close() {
	if m.conn != nil {
		m.conn.Close()
	}
}

func (m *PolicyViolationMonitor) Start(ctx context.Context) error {
	req := &observerpb.GetFlowsRequest{
		Number: 0, // Stream continuously
		Since:  timestamppb.New(time.Now().Add(-m.config.Since)),
		Follow: true,
		Whitelist: []*flowpb.FlowFilter{
			{
				// Filter for policy dropped flows across ALL namespaces
				Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED},
			},
		},
	}

	// Only add namespace filter if explicitly specified
	// By default, monitor ALL namespaces for policy violations
	if m.config.Namespace != "" {
		log.Printf("Filtering to namespace: %s", m.config.Namespace)
		req.Whitelist[0].SourcePod = []string{m.config.Namespace + "/"}
		req.Whitelist[0].DestinationPod = []string{m.config.Namespace + "/"}
	} else {
		log.Printf("Monitoring ALL namespaces for policy violations")
	}

	stream, err := m.client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get flows: %w", err)
	}

	log.Println("Connected to Hubble Relay, monitoring network policy violations...")

	for {
		// stream.Recv() blocks until a message arrives or an error occurs
		// The gRPC library will properly handle context cancellation
		resp, err := stream.Recv()
		if err != nil {
			// Check if context was cancelled (normal shutdown)
			if ctx.Err() != nil {
				log.Println("Context cancelled, stopping stream...")
				return nil
			}
			// Check if it's EOF (connection closed by server)
			if err == io.EOF {
				return io.EOF
			}
			// Any other error
			return fmt.Errorf("failed to receive flow: %w", err)
		}

		flow := resp.GetFlow()
		if flow == nil {
			continue
		}

		m.handlePolicyViolation(flow)
	}
}

func (m *PolicyViolationMonitor) handlePolicyViolation(flow *flowpb.Flow) {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return
	}

	// Extract source and destination IPs from the IP layer
	var sourceIP, destIP string
	if flow.GetIP() != nil {
		sourceIP = flow.GetIP().GetSource()
		destIP = flow.GetIP().GetDestination()
	}

	// Get traffic direction
	trafficDirection := flow.GetTrafficDirection().String()

	// Get policy match type (if available)
	var policyMatchType string
	if matchType := flow.GetPolicyMatchType(); matchType != 0 {
		policyMatchType = policyMatchTypeToString(matchType)
	}

	// Extract denied_by policies based on traffic direction
	deniedBy := m.extractDeniedByPolicies(flow)

	violation := PolicyViolation{
		Timestamp:        flow.GetTime().AsTime().Format(time.RFC3339),
		EventType:        flow.GetEventType().String(),
		NodeName:         flow.GetNodeName(),
		Source:           m.extractEndpointInfo(flow.GetSource(), sourceIP),
		Destination:      m.extractEndpointInfo(flow.GetDestination(), destIP),
		Protocol:         m.extractProtocolInfo(flow),
		TrafficDirection: trafficDirection,
		PolicyMatchType:  policyMatchType,
		PolicyInfo:       m.getPolicyInfo(flow),
		DeniedBy:         deniedBy,
		DropReason:       flow.GetDropReasonDesc().String(),
		Summary:          flow.GetSummary(),
		Verdict:          flow.GetVerdict().String(),
	}

	// Add detailed flow information if verbose mode is enabled
	if m.config.Verbose {
		violation.FlowDetails = m.extractFlowDetails(flow)
	}

	// Output as JSON
	jsonOutput, err := json.Marshal(violation)
	if err != nil {
		log.Printf("Error marshaling violation to JSON: %v", err)
		return
	}

	fmt.Println(string(jsonOutput))
}

func (m *PolicyViolationMonitor) extractDeniedByPolicies(flow *flowpb.Flow) []PolicyReference {
	var policies []PolicyReference

	// Check egress denied policies
	// These fields are only populated if Hubble is configured with --enable-hubble-policy-verdicts
	egressDenied := flow.GetEgressDeniedBy()
	for _, policy := range egressDenied {
		if policy != nil {
			policies = append(policies, PolicyReference{
				Name:      policy.GetName(),
				Namespace: policy.GetNamespace(),
				Labels:    policy.GetLabels(),
			})
		}
	}

	// Check ingress denied policies
	ingressDenied := flow.GetIngressDeniedBy()
	for _, policy := range ingressDenied {
		if policy != nil {
			policies = append(policies, PolicyReference{
				Name:      policy.GetName(),
				Namespace: policy.GetNamespace(),
				Labels:    policy.GetLabels(),
			})
		}
	}

	// Return nil instead of empty slice for cleaner JSON output
	if len(policies) == 0 {
		return nil
	}

	return policies
}

func (m *PolicyViolationMonitor) extractEndpointInfo(endpoint *flowpb.Endpoint, ip string) EndpointInfo {
	if endpoint == nil {
		return EndpointInfo{IP: ip}
	}

	return EndpointInfo{
		Namespace: endpoint.GetNamespace(),
		PodName:   endpoint.GetPodName(),
		Labels:    endpoint.GetLabels(),
		ID:        endpoint.GetID(),
		IP:        ip,
	}
}

func (m *PolicyViolationMonitor) extractProtocolInfo(flow *flowpb.Flow) ProtocolInfo {
	l4 := flow.GetL4()
	if l4 == nil {
		return ProtocolInfo{Type: "unknown"}
	}

	switch l4.GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		tcp := l4.GetTCP()
		return ProtocolInfo{
			Type:            "TCP",
			SourcePort:      tcp.GetSourcePort(),
			DestinationPort: tcp.GetDestinationPort(),
		}
	case *flowpb.Layer4_UDP:
		udp := l4.GetUDP()
		return ProtocolInfo{
			Type:            "UDP",
			SourcePort:      udp.GetSourcePort(),
			DestinationPort: udp.GetDestinationPort(),
		}
	case *flowpb.Layer4_ICMPv4:
		icmp := l4.GetICMPv4()
		return ProtocolInfo{
			Type:     "ICMPv4",
			ICMPType: icmp.GetType(),
			ICMPCode: icmp.GetCode(),
		}
	case *flowpb.Layer4_ICMPv6:
		icmp := l4.GetICMPv6()
		return ProtocolInfo{
			Type:     "ICMPv6",
			ICMPType: icmp.GetType(),
			ICMPCode: icmp.GetCode(),
		}
	default:
		return ProtocolInfo{Type: "unknown"}
	}
}

func (m *PolicyViolationMonitor) extractFlowDetails(flow *flowpb.Flow) *FlowDetails {
	details := &FlowDetails{}

	if flow.GetEthernet() != nil {
		eth := flow.GetEthernet()
		details.EthernetSource = eth.GetSource()
		details.EthernetDestination = eth.GetDestination()
	}

	if flow.GetIP() != nil {
		ip := flow.GetIP()
		details.IPSource = ip.GetSource()
		details.IPDestination = ip.GetDestination()
	}

	return details
}

func (m *PolicyViolationMonitor) getPolicyInfo(flow *flowpb.Flow) string {
	policyMatchType := flow.GetPolicyMatchType()
	if policyMatchType != 0 {
		return fmt.Sprintf("Policy match type: %s", policyMatchTypeToString(policyMatchType))
	}

	dropReason := flow.GetDropReasonDesc()
	if dropReason != flowpb.DropReason_DROP_REASON_UNKNOWN {
		return fmt.Sprintf("Drop reason: %s", dropReason.String())
	}

	return "Network policy denied"
}