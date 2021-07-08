package domain

type AccessControlRule struct {
	Principal   Principal
	Permissions []Permission
	Resource    Resource
}
