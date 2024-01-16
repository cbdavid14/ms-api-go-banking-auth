package domain

import "strings"

type RolePermission struct {
	rolePermissions map[string][]string
}

func GetRolePermissions() RolePermission {
	permissions := map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomer", "NewTransaction"},
	}
	return RolePermission{permissions}
}

func (p RolePermission) IsAuthorizedFor(role string, routeName string) bool {
	perms := p.rolePermissions[role]
	for _, r := range perms {
		if r == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false
}
