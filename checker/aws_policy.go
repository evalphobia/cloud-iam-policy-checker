package checker

import (
	"encoding/json"

	"github.com/evalphobia/aws-sdk-go-wrapper/iam"
)

const (
	entityUser  = "user"
	entityGroup = "group"
	entityRole  = "role"
)

// AwsPolicy contains aws policy data.
type AwsPolicy struct {
	ARN                   string
	PolicyName            string
	Policy                iam.PolicyDocument
	PolicyActions         []string
	PolicyResourceActions []ResourceAction

	AttachedUsers      []string
	AttachedGroups     []Group
	AttachedGroupUsers []string
	AttachedAllUsers   []string
	AttachedRoles      []string
}

func (p AwsPolicy) GetEntityAndType() (typ string, entities []string) {
	switch {
	case len(p.AttachedUsers) != 0:
		return entityUser, p.AttachedUsers
	case len(p.AttachedGroups) != 0:
		return entityGroup, GetGroupNames(p.AttachedGroups)
	case len(p.AttachedRoles) != 0:
		return entityRole, p.AttachedRoles
	default:
		return "", nil
	}
}

// SetPolicy sets resources and actions from PolicyDcoument.
func (p *AwsPolicy) SetPolicy(pd iam.PolicyDocument) {
	p.Policy = pd
	for _, s := range pd.Statement {
		p.PolicyActions = append(p.PolicyActions, s.Action...)
		p.PolicyResourceActions = append(p.PolicyResourceActions, ResourceAction{
			Resources: s.Resource,
			Actions:   s.Action,
		})
	}
}

// SetEntityList sets policy entities.
func (p *AwsPolicy) SetEntityList(list []iam.PolicyEntity) {
	for i, e := range list {
		switch {
		case e.IsUser():
			p.AttachedUsers = append(p.AttachedUsers, e.Name)
			p.AttachedAllUsers = append(p.AttachedAllUsers, e.Name)
		case e.IsGroup():
			p.AttachedGroups = append(p.AttachedGroups, Group{
				Name: e.Name,
			})
		case e.IsRole():
			p.AttachedRoles = append(p.AttachedRoles, e.Name)
		}
		list[i] = e
	}
}

// Group contains group name and users.
type Group struct {
	Name  string
	Users []string
}

func (g Group) String() string {
	return g.Name
}

// GetGroupNames gets group name list from groups.
func GetGroupNames(list []Group) []string {
	result := make([]string, len(list))
	for i, g := range list {
		result[i] = g.Name
	}
	return result
}

// ResourceAction contains Action and Resource list.
type ResourceAction struct {
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// GetResourceAndAction returns resource and action of policy.
func GetResourceAndAction(list []ResourceAction) []string {
	result := make([]string, 0, len(list))
	for _, r := range list {
		byt, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			continue
		}
		result = append(result, string(byt))
	}
	return result
}
