package iamsnitch

import (
	"encoding/json"

	"gorm.io/gorm"
)

type ActionList struct {
	gorm.Model
	StatementID uint
	Items       []Action
}

type Action struct {
	gorm.Model
	ActionListID uint
	Value        string
}

func (a *ActionList) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	slicePayload, ok := v.([]interface{})
	if ok {
		for _, item := range slicePayload {
			a.Items = append(a.Items, Action{Value: item.(string)})
		}
	}

	strPayload, ok := v.(string)
	if ok {
		a.Items = append(a.Items, Action{Value: strPayload})
	}

	return nil
}
