package checker

import (
	"strings"
)

// TargetService checks the action cotains target service.
type TargetService struct {
	Map map[string]interface{}
}

func newTargetService(services []string) TargetService {
	m := make(map[string]interface{})
	for _, v := range services {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		m[v] = struct{}{}
	}

	return TargetService{
		Map: m,
	}
}

// HasTargetInActions checks if given actions contains target service.
func (s TargetService) HasTargetInActions(actions []string) bool {
	if !s.hasService() {
		return false
	}

	for _, action := range actions {
		if s.isTargetAction(action) {
			return true
		}
	}

	return false
}

func (s TargetService) isTargetAction(action string) bool {
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		return false
	}
	return s.isTarget(parts[0])
}

func (s TargetService) isTarget(service string) bool {
	_, ok := s.Map[service]
	return ok
}

func (s TargetService) hasService() bool {
	return len(s.Map) != 0
}
