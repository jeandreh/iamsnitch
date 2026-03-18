package aws

import (
	"encoding/json"
	"fmt"
)

type Statement struct {
	Effect     string                            `json:"Effect"`
	Principals PrincipalList                     `json:"Principal"`
	Actions    []string                          `json:"Action"`
	NotActions []string                          `json:"NotAction"` // Added NotAction field
	Resources  []string                          `json:"Resource"`
	Conditions map[string]map[string]interface{} `json:"Condition"`
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
		// Check for NotAction as well
		actions, ok = mapStmt["NotAction"]
		if !ok {
			// Debug: print the available keys
			var keys []string
			for k := range mapStmt {
				keys = append(keys, k)
			}
			return fmt.Errorf("field Statement.Action or NotAction is invalid in statement JSON payload. Available fields: %v", keys)
		}
	}
	if err := s.unmarshalActions(actions); err != nil {
		return err
	}

	// Also check for NotAction separately if both are present
	notActions, ok := mapStmt["NotAction"]
	if ok {
		if err := s.unmarshalNotActions(notActions); err != nil {
			return err
		}
	}

	principals, ok := mapStmt["Principal"]
	if ok {
		if err := s.unmarshalPrincipalList(principals); err != nil {
			return err
		}
	}

	resources, ok := mapStmt["Resource"]
	if ok {
		if err := s.unmarshalResources(resources); err != nil {
			return err
		}
	}

	conditions, ok := mapStmt["Condition"]
	if ok {
		if err := s.unmarshalConditions(conditions); err != nil {
			return err
		}
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

func (s *Statement) unmarshalNotActions(data interface{}) error {
	switch pl := data.(type) {
	case []interface{}:
		for _, i := range pl {
			spl, ok := i.(string)
			if !ok {
				return fmt.Errorf("NotActions is not a list of string")
			}
			s.NotActions = append(s.NotActions, spl)
		}
		return nil
	case string:
		s.NotActions = append(s.NotActions, pl)
		return nil
	}
	return fmt.Errorf("unknown NotActions format")
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

func (s *Statement) unmarshalConditions(data interface{}) error {
	conditionsMap, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Condition field is not a map")
	}

	s.Conditions = make(map[string]map[string]interface{})

	for operator, conditionKeysData := range conditionsMap {
		conditionKeys, ok := conditionKeysData.(map[string]interface{})
		if !ok {
			return fmt.Errorf("Condition operator %s value is not a map", operator)
		}

		s.Conditions[operator] = conditionKeys
	}

	return nil
}
