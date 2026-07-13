package correlation

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"aegis-edr/internal/telemetry"
)

type ProcessNode struct {
	PID          int32
	ParentPID    int32
	BinaryPath   string
	CommandLine  string
	Username     string
	LaunchedAt   time.Time
	FileChanges  []FileActivity
	NetConnects  []NetworkActivity
	RegistryKeys []RegistryActivity
	Alerts       []AlertActivity
	Children     []*ProcessNode
}

type FileActivity struct {
	FilePath   string
	Action     string
	OccurredAt time.Time
}

type NetworkActivity struct {
	Protocol   string
	RemoteIP   string
	RemotePort int32
	OccurredAt time.Time
}

type RegistryActivity struct {
	KeyPath    string
	Action     string
	OccurredAt time.Time
}

type AlertActivity struct {
	RuleName    string
	Description string
	OccurredAt  time.Time
}

type TimelineItem struct {
	Timestamp   time.Time
	Category    string
	Description string
}

type Engine struct {
	mu     sync.RWMutex
	nodes  map[int32]*ProcessNode
	window time.Duration
}

func NewEngine(window time.Duration) *Engine {
	return &Engine{
		nodes:  make(map[int32]*ProcessNode),
		window: window,
	}
}

func (e *Engine) Correlate(ev *telemetry.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for pid, node := range e.nodes {
		if now.Sub(node.LaunchedAt) > e.window {
			delete(e.nodes, pid)
		}
	}

	switch ev.Type {
	case "process":
		node := &ProcessNode{
			PID:          ev.ProcessID,
			ParentPID:    ev.ParentID,
			BinaryPath:   ev.BinaryPath,
			CommandLine:  ev.CommandLine,
			Username:     ev.Username,
			LaunchedAt:   ev.Timestamp,
			FileChanges:  make([]FileActivity, 0),
			NetConnects:  make([]NetworkActivity, 0),
			RegistryKeys: make([]RegistryActivity, 0),
			Alerts:       make([]AlertActivity, 0),
			Children:     make([]*ProcessNode, 0),
		}
		e.nodes[ev.ProcessID] = node

		if parent, exists := e.nodes[ev.ParentID]; exists {
			parent.Children = append(parent.Children, node)
		}

	case "file":
		if node, exists := e.nodes[ev.ProcessID]; exists {
			node.FileChanges = append(node.FileChanges, FileActivity{
				FilePath:   ev.FilePath,
				Action:     ev.FileAction,
				OccurredAt: ev.Timestamp,
			})
		}

	case "network":
		if node, exists := e.nodes[ev.ProcessID]; exists {
			node.NetConnects = append(node.NetConnects, NetworkActivity{
				Protocol:   ev.Protocol,
				RemoteIP:   ev.RemoteIP,
				RemotePort: ev.RemotePort,
				OccurredAt: ev.Timestamp,
			})
		}

	case "registry":
		if node, exists := e.nodes[ev.ProcessID]; exists {
			node.RegistryKeys = append(node.RegistryKeys, RegistryActivity{
				KeyPath:    ev.FilePath,
				Action:     ev.FileAction,
				OccurredAt: ev.Timestamp,
			})
		}
	}
}

func (e *Engine) RecordAlert(pid int32, ruleName, desc string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if node, exists := e.nodes[pid]; exists {
		node.Alerts = append(node.Alerts, AlertActivity{
			RuleName:    ruleName,
			Description: desc,
			OccurredAt:  time.Now(),
		})
	}
}

func (e *Engine) ReconstructTimeline(pid int32) ([]TimelineItem, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	node, exists := e.nodes[pid]
	if !exists {
		return nil, fmt.Errorf("process node %d not found in active window", pid)
	}

	var items []TimelineItem
	e.collectTimeline(node, &items)

	sort.Slice(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})

	return items, nil
}

func (e *Engine) collectTimeline(node *ProcessNode, items *[]TimelineItem) {
	*items = append(*items, TimelineItem{
		Timestamp:   node.LaunchedAt,
		Category:    "PROCESS",
		Description: fmt.Sprintf("Process executed: %s (args: %s) by %s", node.BinaryPath, node.CommandLine, node.Username),
	})

	for _, f := range node.FileChanges {
		*items = append(*items, TimelineItem{
			Timestamp:   f.OccurredAt,
			Category:    "FILE",
			Description: fmt.Sprintf("File %s: %s", f.Action, f.FilePath),
		})
	}

	for _, n := range node.NetConnects {
		*items = append(*items, TimelineItem{
			Timestamp:   n.OccurredAt,
			Category:    "NETWORK",
			Description: fmt.Sprintf("Network connection: %s %s:%d", n.Protocol, n.RemoteIP, n.RemotePort),
		})
	}

	for _, r := range node.RegistryKeys {
		*items = append(*items, TimelineItem{
			Timestamp:   r.OccurredAt,
			Category:    "REGISTRY",
			Description: fmt.Sprintf("Registry %s: %s", r.Action, r.KeyPath),
		})
	}

	for _, a := range node.Alerts {
		*items = append(*items, TimelineItem{
			Timestamp:   a.OccurredAt,
			Category:    "ALERT",
			Description: fmt.Sprintf("Alert %s triggered: %s", a.RuleName, a.Description),
		})
	}

	for _, child := range node.Children {
		e.collectTimeline(child, items)
	}
}

func (e *Engine) GroupAlerts(pid int32) ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	node, exists := e.nodes[pid]
	if !exists {
		return nil, fmt.Errorf("process node %d not found in active window", pid)
	}

	var alerts []string
	e.collectAlertNames(node, &alerts)
	return alerts, nil
}

func (e *Engine) collectAlertNames(node *ProcessNode, list *[]string) {
	for _, a := range node.Alerts {
		*list = append(*list, a.RuleName)
	}
	for _, child := range node.Children {
		e.collectAlertNames(child, list)
	}
}
