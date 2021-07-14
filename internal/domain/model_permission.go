package domain

type Permission struct {
	Action     Action
	GrantChain []GrantIface
}
