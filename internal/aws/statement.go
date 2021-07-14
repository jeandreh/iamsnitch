package aws

import (
	"encoding/json"
	"fmt"
)

type Statement struct {
	Effect     string        `json:"Effect"`
	Principals PrincipalList `json:"Principal"`
	Actions    []string      `json:"Action"`
	Resources  []string      `json:"Resource"`
}

func (s *Statement) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	mapStmt, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid Statement JSON payload")
	}

	effect, ok := mapStmt["Effect"].(string)
	if !ok {
		return fmt.Errorf("field Statement.Effect is invalid in statement JSON payload")
	}
	s.Effect = effect

	actions, ok := mapStmt["Action"]
	if !ok {
		return fmt.Errorf("field Statement.Action is invalid in statement JSON payload")
	}
	if err := s.unmarshalActions(actions); err != nil {
		return err
	}

	principals, ok := mapStmt["Principal"]
	if ok {
		if err := s.unmarshalPrincipalList(principals); err != nil {
			return err
		}
	}

	resources, ok := mapStmt["Resource"]
	if ok {
		return s.unmarshalResources(resources)
	}
	return nil
}

func (s *Statement) unmarshalPrincipalList(data interface{}) error {
	switch pl := data.(type) {
	case []interface{}:
		for _, item := range pl {
			if err := s.Principals.parsePrincipalList(item); err != nil {
				return err
			}
		}
	case interface{}:
		return s.Principals.parsePrincipalList(pl)
	}
	return nil
}

func (s *Statement) unmarshalActions(data interface{}) error {
	switch pl := data.(type) {
	case []interface{}:
		for _, i := range pl {
			spl, ok := i.(string)
			if !ok {
				return fmt.Errorf("Actions is not a list of string")
			}
			s.Actions = append(s.Actions, spl)
		}
		return nil
	case string:
		s.Actions = append(s.Actions, pl)
		return nil
	}
	return fmt.Errorf("unknown Actions format")
}

func (s *Statement) unmarshalResources(data interface{}) error {
	switch pl := data.(type) {
	case []interface{}:
		for _, i := range pl {
			spl, ok := i.(string)
			if !ok {
				return fmt.Errorf("Resources is not a list of string")
			}
			s.Resources = append(s.Resources, spl)
		}
		return nil
	case string:
		s.Resources = append(s.Resources, pl)
		return nil
	}
	return fmt.Errorf("unknown Resources format")
}
