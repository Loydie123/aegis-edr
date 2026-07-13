package nextgen

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"

	"aegis-edr/internal/telemetry"
)

type NodeType string

const (
	NodeProcess    NodeType = "PROCESS"
	NodeFile       NodeType = "FILE"
	NodeRegistry   NodeType = "REGISTRY"
	NodeService    NodeType = "SERVICE"
	NodeDriver     NodeType = "DRIVER"
	NodeNetwork    NodeType = "NETWORK"
	NodeDNS        NodeType = "DNS"
	NodeUser       NodeType = "USER"
	NodeTask       NodeType = "TASK"
	NodeUSB        NodeType = "USB"
	NodeIntel      NodeType = "INTEL"
	NodePolicy     NodeType = "POLICY"
)

type Node struct {
	ID         string
	Type       NodeType
	Timestamp  time.Time
	Properties map[string]interface{}
	Edges      []*Edge
}

type Edge struct {
	Type      string
	Target    *Node
	Timestamp time.Time
}

type CorrelationRule struct {
	ID          string
	Name        string
	Sequence    []NodeType
	TimeWindow  time.Duration
	MITREIDs    []string
	Description string
}

type Alert struct {
	RuleID          string    `json:"rule_id"`
	RuleName        string    `json:"rule_name"`
	RootPID         int32     `json:"root_pid"`
	RiskScore       float64   `json:"risk_score"`
	ConfidenceScore float64   `json:"confidence_score"`
	MITREIDs        []string  `json:"mitre_ids"`
	Timeline        []string  `json:"timeline"`
	OccurredAt      time.Time `json:"occurred_at"`
}

type Shard struct {
	mu          sync.RWMutex
	nodes       map[string]*Node
	alertsCount map[string]int
}

type Engine struct {
	shards      []*Shard
	shardCount  int
	rules       []CorrelationRule
	window      time.Duration
	suppressed  map[string]bool
	suppressMu  sync.RWMutex
	alertsChan  chan Alert
}

func NewEngine(shardCount int, window time.Duration, alertsChan chan Alert) *Engine {
	e := &Engine{
		shardCount: shardCount,
		shards:     make([]*Shard, shardCount),
		window:     window,
		suppressed: make(map[string]bool),
		alertsChan: alertsChan,
	}
	for i := 0; i < shardCount; i++ {
		e.shards[i] = &Shard{
			nodes:       make(map[string]*Node),
			alertsCount: make(map[string]int),
		}
	}
	return e
}

func (e *Engine) AddRule(r CorrelationRule) {
	e.rules = append(e.rules, r)
}

func (e *Engine) SuppressAlert(ruleID string, target string) {
	e.suppressMu.Lock()
	defer e.suppressMu.Unlock()
	e.suppressed[ruleID+":"+target] = true
}

func (e *Engine) getShard(id string) *Shard {
	h := fnv.New32a()
	h.Write([]byte(id))
	idx := h.Sum32() % uint32(e.shardCount)
	return e.shards[idx]
}

func (e *Engine) Ingest(ctx context.Context, ev *telemetry.Event) {
	nodeID := fmt.Sprintf("%s:%d", string(ev.Type), ev.ProcessID)
	if ev.Type != "process" {
		nodeID = fmt.Sprintf("%s:%s", string(ev.Type), ev.FilePath)
		if ev.Type == "network" {
			nodeID = fmt.Sprintf("%s:%s:%d", string(ev.Type), ev.RemoteIP, ev.RemotePort)
		}
	}

	shard := e.getShard(nodeID)
	shard.mu.Lock()

	now := time.Now()
	for id, n := range shard.nodes {
		if now.Sub(n.Timestamp) > e.window {
			delete(shard.nodes, id)
		}
	}

	node := &Node{
		ID:         nodeID,
		Type:       NodeType(strings.ToUpper(ev.Type)),
		Timestamp:  ev.Timestamp,
		Properties: make(map[string]interface{}),
		Edges:      make([]*Edge, 0),
	}

	node.Properties["binary_path"] = ev.BinaryPath
	node.Properties["command_line"] = ev.CommandLine
	node.Properties["username"] = ev.Username
	node.Properties["pid"] = ev.ProcessID
	node.Properties["parent_id"] = ev.ParentID

	shard.nodes[nodeID] = node
	shard.mu.Unlock()

	if ev.Type == "process" && ev.ParentID > 0 {
		parentID := fmt.Sprintf("process:%d", ev.ParentID)
		parentShard := e.getShard(parentID)
		parentShard.mu.Lock()
		if parentNode, exists := parentShard.nodes[parentID]; exists {
			parentNode.Edges = append(parentNode.Edges, &Edge{
				Type:      "SPAWNED",
				Target:    node,
				Timestamp: ev.Timestamp,
			})
			node.Edges = append(node.Edges, &Edge{
				Type:      "PARENT_OF",
				Target:    parentNode,
				Timestamp: ev.Timestamp,
			})
		}
		parentShard.mu.Unlock()
	}

	e.evaluateRules(ctx, node)
}

func (e *Engine) evaluateRules(ctx context.Context, triggerNode *Node) {
	for _, rule := range e.rules {
		matched, chain := e.checkSequence(triggerNode, rule.Sequence, 0, make([]*Node, 0), rule.TimeWindow)
		if matched {
			e.triggerAlert(rule, chain)
		}
	}
}

func (e *Engine) checkSequence(n *Node, seq []NodeType, idx int, chain []*Node, window time.Duration) (bool, []*Node) {
	if idx >= len(seq) {
		return true, chain
	}

	if n.Type != seq[idx] {
		return false, nil
	}

	newChain := append(chain, n)
	if idx == len(seq)-1 {
		return true, newChain
	}

	for _, edge := range n.Edges {
		if edge.Target == nil {
			continue
		}
		if edge.Target.Timestamp.Sub(n.Timestamp) > window {
			continue
		}
		matched, finalChain := e.checkSequence(edge.Target, seq, idx+1, newChain, window)
		if matched {
			return true, finalChain
		}
	}

	return false, nil
}

func (e *Engine) triggerAlert(rule CorrelationRule, chain []*Node) {
	if len(chain) == 0 {
		return
	}

	var rootNode *Node
	for _, node := range chain {
		if rootNode == nil || node.Timestamp.Before(rootNode.Timestamp) {
			rootNode = node
		}
	}

	rootPID := int32(0)
	if rootNode != nil {
		pidVal, ok := rootNode.Properties["pid"]
		if ok {
			if val, isInt := pidVal.(int32); isInt {
				rootPID = val
			}
		}
	}

	e.suppressMu.RLock()
	key := fmt.Sprintf("%s:%d", rule.ID, rootPID)
	isSuppressed := e.suppressed[key]
	e.suppressMu.RUnlock()

	if isSuppressed {
		return
	}

	var timeline []string
	riskScore := 0.0
	confidenceScore := 0.85

	for i, node := range chain {
		timeline = append(timeline, fmt.Sprintf("[%s] %s (ID: %s)", node.Timestamp.Format(time.RFC3339), string(node.Type), node.ID))
		riskScore += 1.5 * float64(i+1)
	}

	if riskScore > 10.0 {
		riskScore = 10.0
	}

	alert := Alert{
		RuleID:          rule.ID,
		RuleName:        rule.Name,
		RootPID:         rootPID,
		RiskScore:       riskScore,
		ConfidenceScore: confidenceScore,
		MITREIDs:        rule.MITREIDs,
		Timeline:        timeline,
		OccurredAt:      time.Now(),
	}

	select {
	case e.alertsChan <- alert:
	default:
	}
}

func (e *Engine) ReconstructTimeline(pid int32) ([]string, error) {
	nodeID := fmt.Sprintf("process:%d", pid)
	shard := e.getShard(nodeID)
	shard.mu.RLock()
	node, exists := shard.nodes[nodeID]
	shard.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("process pid %d not found", pid)
	}

	var timeline []string
	visited := make(map[string]bool)
	e.dfsTimeline(node, visited, &timeline)

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i] < timeline[j]
	})

	return timeline, nil
}

func (e *Engine) dfsTimeline(n *Node, visited map[string]bool, timeline *[]string) {
	if visited[n.ID] {
		return
	}
	visited[n.ID] = true

	*timeline = append(*timeline, fmt.Sprintf("[%s] [%s] %s", n.Timestamp.Format(time.RFC3339), string(n.Type), n.ID))

	for _, edge := range n.Edges {
		if edge.Target != nil {
			e.dfsTimeline(edge.Target, visited, timeline)
		}
	}
}
