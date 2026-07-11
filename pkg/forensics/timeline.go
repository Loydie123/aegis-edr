package forensics

import (
	"fmt"
	"sort"
	"time"

	"aegis-edr/pkg/storage"
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
	var events []TimelineEvent

	procRows, err := tb.store.DB().Query(
		"SELECT binary_path, command_line, username, launched_at FROM processes WHERE launched_at BETWEEN ? AND ?",
		start, end,
	)
	if err == nil {
		defer procRows.Close()
		for procRows.Next() {
			var binPath, cmdLine, username string
			var launchedAt time.Time
			if err := procRows.Scan(&binPath, &cmdLine, &username, &launchedAt); err == nil {
				events = append(events, TimelineEvent{
					Timestamp:   launchedAt,
					Category:    "PROCESS",
					Description: fmt.Sprintf("Process executed: %s (args: %s) by user %s", binPath, cmdLine, username),
				})
			}
		}
	}

	fileRows, err := tb.store.DB().Query(
		"SELECT file_path, action, occurred_at FROM file_modifications WHERE occurred_at BETWEEN ? AND ?",
		start, end,
	)
	if err == nil {
		defer fileRows.Close()
		for fileRows.Next() {
			var filePath, action string
			var occurredAt time.Time
			if err := fileRows.Scan(&filePath, &action, &occurredAt); err == nil {
				events = append(events, TimelineEvent{
					Timestamp:   occurredAt,
					Category:    "FILE",
					Description: fmt.Sprintf("File %s: %s", action, filePath),
				})
			}
		}
	}

	netRows, err := tb.store.DB().Query(
		"SELECT protocol, local_ip, local_port, remote_ip, remote_port, occurred_at FROM network_connections WHERE occurred_at BETWEEN ? AND ?",
		start, end,
	)
	if err == nil {
		defer netRows.Close()
		for netRows.Next() {
			var protocol, localIP, remoteIP string
			var localPort, remotePort int
			var occurredAt time.Time
			if err := netRows.Scan(&protocol, &localIP, &localPort, &remoteIP, &remotePort, &occurredAt); err == nil {
				events = append(events, TimelineEvent{
					Timestamp:   occurredAt,
					Category:    "NETWORK",
					Description: fmt.Sprintf("Network connection: %s %s:%d -> %s:%d", protocol, localIP, localPort, remoteIP, remotePort),
				})
			}
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events, nil
}
