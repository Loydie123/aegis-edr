package core

import (
	"fmt"
	"reflect"
	"sync"
)

type DIContainer struct {
	mu        sync.RWMutex
	instances map[reflect.Type]interface{}
}

func NewDIContainer() *DIContainer {
	return &DIContainer{
		instances: make(map[reflect.Type]interface{}),
	}
}

func Register[T interface{}](c *DIContainer, instance T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := reflect.TypeOf((*T)(nil)).Elem()
	c.instances[t] = instance
}

func Resolve[T interface{}](c *DIContainer) (T, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t := reflect.TypeOf((*T)(nil)).Elem()
	instance, exists := c.instances[t]
	if !exists {
		var zero T
		return zero, fmt.Errorf("dependency of type %s not registered", t.String())
	}
	return instance.(T), nil
}
