package iamsnitch

import (
	"encoding/json"

	"gorm.io/gorm"
)

type ResourceList struct {
	gorm.Model
	StatementID uint
	Items       []Resource
}

type Resource struct {
	gorm.Model
	ResourceListID uint
	ARN            string
}

func (r *ResourceList) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	slicePayload, ok := v.([]interface{})
	if ok {
		for _, item := range slicePayload {
			r.Items = append(r.Items, Resource{ARN: item.(string)})
		}
	}

	strPayload, ok := v.(string)
	if ok {
		r.Items = append(r.Items, Resource{ARN: strPayload})
	}

	return nil
}
