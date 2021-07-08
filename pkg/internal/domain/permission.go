package domain

type Permission struct {
	Action     string
	GrantChain []GrantIface
}
