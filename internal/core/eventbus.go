package core

import (
	"sync"
)

type Event struct {
	Topic string
	Data  interface{}
}

type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]chan Event
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string][]chan Event),
	}
}

func (eb *EventBus) Subscribe(topic string) chan Event {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	ch := make(chan Event, 100)
	eb.subscribers[topic] = append(eb.subscribers[topic], ch)
	return ch
}

func (eb *EventBus) Publish(event Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	subs, exists := eb.subscribers[event.Topic]
	if !exists {
		return
	}
	for _, sub := range subs {
		select {
		case sub <- event:
		default:
		}
	}
}
