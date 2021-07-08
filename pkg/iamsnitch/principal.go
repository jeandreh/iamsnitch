package iamsnitch

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
)

type PrincipalList struct {
	gorm.Model
	StatementID uint
	Items       []Principal
}

type Principal struct {
	gorm.Model
	PrincipalListID uint
	Service         []Value
	AWS             []Value
	Federated       []Value
	CanonicalUser   []Value
}

type Value struct {
	gorm.Model
	PrincipalID uint
	Value       string
}

func (a *PrincipalList) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	slicePayload, ok := v.([]interface{})
	if ok {
		for _, item := range slicePayload {
			a.addPrincipal(item)
		}
	} else {
		if err := a.addPrincipal(v); err != nil {
			return err
		}
	}
	return nil
}

func (a *PrincipalList) addPrincipal(v interface{}) error {
	pMap, ok := v.(map[string]interface{})
	if ok {
		pt := []string{
			"Service",
			"AWS",
			"CanonicalUser",
			"Federated",
		}
		p := Principal{}
		for _, t := range pt {
			entry, ok := pMap[t]
			if ok {
				sl, ok := entry.([]string)
				if ok {
					p.add(t, sl...)
				} else {
					s, ok := entry.(string)
					if ok {
						p.add(t, s)
					} else {
						return fmt.Errorf("unable to add %v to Principal", entry)
					}
				}
			}
		}
		a.Items = append(a.Items, p)
	}
	return nil
}

func (a *Principal) toValue(s []string) []Value {
	vl := make([]Value, 0, len(s))
	for _, e := range s {
		vl = append(vl, Value{Value: e})
	}
	return vl
}

func (p *Principal) add(key string, values ...string) {
	v := p.toValue(values)
	switch key {
	case "Service":
		p.Service = append(p.Service, v...)
	case "AWS":
		p.AWS = append(p.AWS, v...)
	case "Federated":
		p.Federated = append(p.Federated, v...)
	case "CanonicalUser":
		p.CanonicalUser = append(p.CanonicalUser, v...)
	}
}
