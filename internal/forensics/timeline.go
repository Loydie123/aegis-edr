package forensics

import (
	"context"
	"fmt"
	"sort"
	"time"

	"aegis-edr/internal/storage"
)

type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
}

type TimelineBuilder struct {
	store *storage.Storage
}

func NewTimelineBuilder(store *storage.Storage) *TimelineBuilder {
	return &TimelineBuilder{store: store}
}

func (tb *TimelineBuilder) BuildTimeline(start, end time.Time) ([]TimelineEvent, error) {
	ctx := context.Background()
	var events []TimelineEvent

	procList, err := tb.store.QueryProcesses(ctx, start, end)
	if err == nil {
		for _, p := range procList {
			events = append(events, TimelineEvent{
				Timestamp:   p.LaunchedAt,
				Category:    "PROCESS",
				Description: fmt.Sprintf("Process executed: %s (args: %s) by user %s", p.BinaryPath, p.CommandLine, p.Username),
			})
		}
	}

	fileList, err := tb.store.QueryFileModifications(ctx, start, end)
	if err == nil {
		for _, f := range fileList {
			events = append(events, TimelineEvent{
				Timestamp:   f.OccurredAt,
				Category:    "FILE",
				Description: fmt.Sprintf("File %s: %s", f.Action, f.FilePath),
			})
		}
	}

	netList, err := tb.store.QueryNetworkConnections(ctx, start, end)
	if err == nil {
		for _, n := range netList {
			events = append(events, TimelineEvent{
				Timestamp:   n.OccurredAt,
				Category:    "NETWORK",
				Description: fmt.Sprintf("Network connection: %s %s:%d -> %s:%d", n.Protocol, n.LocalIP, n.LocalPort, n.RemoteIP, n.RemotePort),
			})
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events, nil
}
