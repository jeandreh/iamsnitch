package model

type Filter struct {
	Permissions []string
	Resources   []string
	ExactMatch  bool
}
