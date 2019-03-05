package checker

import (
	"encoding/json"
	"strings"

	"github.com/evalphobia/aws-sdk-go-wrapper/iam"
)

// CSV headers
var defaultHeaders = []string{
	"policy_arn",
	"policy_name",
	"policy_action",
	"policy_resource_action",
	"attached_user",
	"attached_group",
	"attached_group_user",
	"attached_all_user",
	"attached_role",
}

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

// SliceString returns []string for CSV row output.
func (p *AwsPolicy) SliceString() []string {
	return []string{
		p.ARN,
		p.PolicyName,
		strings.Join(p.PolicyActions, "\n"),
		strings.Join(GetResourceAndAction(p.PolicyResourceActions), "\n"),
		strings.Join(p.AttachedUsers, "\n"),
		strings.Join(GetGroupNames(p.AttachedGroups), "\n"),
		strings.Join(p.AttachedGroupUsers, "\n"),
		strings.Join(p.AttachedAllUsers, "\n"),
		strings.Join(p.AttachedRoles, "\n"),
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

func toSliceForOutpout(list []*AwsPolicy) [][]string {
	lines := make([][]string, len(list))
	for i, p := range list {
		lines[i] = p.SliceString()
	}
	return lines
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
