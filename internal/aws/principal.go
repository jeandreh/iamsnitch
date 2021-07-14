package aws

import (
	"encoding/json"
	"fmt"
)

type Type string

const (
	Service       Type = "Service"
	AWS           Type = "AWS"
	Federated     Type = "Federated"
	CanonicalUser Type = "CanonicalUser"
)

type PrincipalList struct {
	Items []Principal
}

type Principal struct {
	Type Type
	ID   string
}

func (pl *PrincipalList) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	return pl.parsePrincipalList(v)
}

func (pl *PrincipalList) parsePrincipalList(v interface{}) error {
	pMap, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid Principal found format")
	}

	pt := []Type{
		Service,
		AWS,
		CanonicalUser,
		Federated,
	}
	for _, t := range pt {
		entry, ok := pMap[string(t)]
		if ok {
			il, ok := entry.([]interface{})
			if ok {
				if err := pl.add(t, il...); err != nil {
					return err
				}
			} else {
				if err := pl.add(t, entry); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (pl *PrincipalList) add(key Type, values ...interface{}) error {
	for _, i := range values {
		s, ok := i.(string)
		if !ok {
			return fmt.Errorf("unable to convert %v to Principal", i)
		}
		pl.Items = append(pl.Items, Principal{key, s})
	}
	return nil
}

func (p *Principal) String() string {
	return fmt.Sprintf("%v[%v]", p.Type, p.ID)
}
