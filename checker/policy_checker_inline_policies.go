package checker

import (
	"strings"

	"github.com/evalphobia/aws-sdk-go-wrapper/iam"
)

// CheckInlinePolicies fetches inline policy list.
func (c *PolicyChecker) CheckInlinePolicies() error {
	if err := checkIsDir(c.config.GetOutputFile()); err != nil {
		return err
	}

	var targetList []*AwsPolicy
	users, err := c.fetchUsers()
	if err != nil {
		return err
	}
	targetList = append(targetList, c.fetchInlinePolicyFromUsers(users)...)

	groups, err := c.fetchGroups()
	if err != nil {
		return err
	}
	targetList = append(targetList, c.fetchInlinePolicyFromGroups(groups)...)

	roles, err := c.fetchRoles()
	if err != nil {
		return err
	}
	targetList = append(targetList, c.fetchInlinePolicyFromRoles(roles)...)

	return c.saveInlinePolicies(targetList)
}

// fetchUsers executes iam:ListUsers.
func (c *PolicyChecker) fetchUsers() ([]iam.User, error) {
	c.loggingInfo("invoking `fetchUsers` ...")

	list, err := c.client.ListUsers()
	c.loggingError("Func:[ListUsers] Error:[%s]", err)
	return list, err
}

// fetchGroups executes iam:ListGroups.
func (c *PolicyChecker) fetchGroups() ([]iam.Group, error) {
	c.loggingInfo("invoking `fetchGroups` ...")

	list, err := c.client.ListGroups()
	c.loggingError("Func:[ListGroups] Error:[%s]", err)
	return list, err
}

// fetchRoles executes iam:ListRoles.
func (c *PolicyChecker) fetchRoles() ([]iam.Role, error) {
	c.loggingInfo("invoking `fetchRoles` ...")

	list, err := c.client.ListRoles()
	c.loggingError("Func:[ListRoles] Error:[%s]", err)
	return list, err
}

// fetchInlinePolicyFromUsers fetches inline policies from the users.
func (c *PolicyChecker) fetchInlinePolicyFromUsers(users []iam.User) []*AwsPolicy {
	c.loggingInfo("invoking `fetchInlinePolicyFromUsers` size:[%d] ...", len(users))

	cli := c.client
	targetList := make([]*AwsPolicy, 0, len(users))
	for _, u := range users {
		policies, err := cli.ListUserPolicies(u.UserName)
		switch {
		case err != nil:
			c.loggingError("Func:[ListUserPolicies] Error:[%s], UserName:[%s]", err, u.UserName)
			continue
		case len(policies) == 0:
			continue
		}

		for _, policyName := range policies {
			policy, err := cli.GetUserPolicyDocument(u.UserName, policyName)
			switch {
			case err != nil:
				c.loggingError("Func:[GetUserPolicyDocument] Error:[%s], UserName:[%s], PolicyName:[%s]", err, u.UserName, policyName)
				continue
			case policy == nil:
				c.loggingError("Func:[GetUserPolicyDocument] Error:[EmptyPolicyDocument], UserName:[%s], PolicyName:[%s]", u.UserName, policyName)
				continue
			}

			// filter policies by Resource/Action/Service from config.
			if !c.hasTargetPermission(policy.Statement) {
				continue
			}

			ap := AwsPolicy{
				AttachedUsers: []string{u.UserName},
				PolicyName:    policyName,
			}
			ap.SetPolicy(*policy)
			targetList = append(targetList, &ap)
		}
	}

	return targetList
}

// fetchInlinePolicyFromGroups fetches inline policies from the groups.
func (c *PolicyChecker) fetchInlinePolicyFromGroups(groups []iam.Group) []*AwsPolicy {
	c.loggingInfo("invoking `fetchInlinePolicyFromGroups` size:[%d] ...", len(groups))

	cli := c.client
	targetList := make([]*AwsPolicy, 0, len(groups))
	for _, g := range groups {
		policies, err := cli.ListGroupPolicies(g.GroupName)
		switch {
		case err != nil:
			c.loggingError("Func:[ListGroupPolicies] Error:[%s], GroupName:[%s]", err, g.GroupName)
			continue
		case len(policies) == 0:
			continue
		}

		for _, policyName := range policies {
			policy, err := cli.GetGroupPolicyDocument(g.GroupName, policyName)
			switch {
			case err != nil:
				c.loggingError("Func:[GetGroupPolicyDocument] Error:[%s], GroupName:[%s], PolicyName:[%s]", err, g.GroupName, policyName)
				continue
			case policy == nil:
				c.loggingError("Func:[GetGroupPolicyDocument] Error:[EmptyPolicyDocument], GroupName:[%s], PolicyName:[%s]", g.GroupName, policyName)
				continue
			}

			// filter policies by Resource/Action/Service from config.
			if !c.hasTargetPermission(policy.Statement) {
				continue
			}

			ap := AwsPolicy{
				AttachedGroups: []Group{
					{Name: g.GroupName},
				},
				PolicyName: policyName,
			}
			ap.SetPolicy(*policy)
			targetList = append(targetList, &ap)
		}
	}

	return targetList
}

// fetchInlinePolicyFromRoles fetches inline policies from the roles.
func (c *PolicyChecker) fetchInlinePolicyFromRoles(roles []iam.Role) []*AwsPolicy {
	c.loggingInfo("invoking `fetchInlinePolicyFromRoles` size:[%d] ...", len(roles))

	cli := c.client
	targetList := make([]*AwsPolicy, 0, len(roles))
	for _, r := range roles {
		policies, err := cli.ListRolePolicies(r.RoleName)
		switch {
		case err != nil:
			c.loggingError("Func:[ListRolePolicies] Error:[%s], RoleName:[%s]", err, r.RoleName)
			continue
		case len(policies) == 0:
			continue
		}

		for _, policyName := range policies {
			policy, err := cli.GetRolePolicyDocument(r.RoleName, policyName)
			switch {
			case err != nil:
				c.loggingError("Func:[GetRolePolicyDocument] Error:[%s], RoleName:[%s], PolicyName:[%s]", err, r.RoleName, policyName)
				continue
			case policy == nil:
				c.loggingError("Func:[GetRolePolicyDocument] Error:[EmptyPolicyDocument], GroupName:[%s], PolicyName:[%s]", r.RoleName, policyName)
				continue
			}

			// filter policies by Resource/Action/Service from config.
			if !c.hasTargetPermission(policy.Statement) {
				continue
			}

			ap := AwsPolicy{
				AttachedRoles: []string{r.RoleName},
				PolicyName:    policyName,
			}
			ap.SetPolicy(*policy)
			targetList = append(targetList, &ap)
		}
	}

	return targetList
}

// saveInlinePolicies saves inline policy list results to local file.
func (c *PolicyChecker) saveInlinePolicies(list []*AwsPolicy) error {
	c.loggingInfo("invoking `saveInlinePolicies` size:[%d] ...", len(list))

	f, err := NewFileHandler(c.config.GetOutputFile())
	if err != nil {
		return err
	}

	// CSV headers
	headers := []string{
		"entity_type",
		"entity_name",
		"policy_name",
		"policy_action",
		"policy_resource_action",
	}

	// CSV row
	fnCols := func(p *AwsPolicy) []string {
		typ, entities := p.GetEntityAndType()
		return []string{
			typ,
			strings.Join(entities, "\n"),
			p.PolicyName,
			strings.Join(p.PolicyActions, "\n"),
			strings.Join(GetResourceAndAction(p.PolicyResourceActions), "\n"),
		}
	}

	return f.WriteAll(headers, toSliceForOutpout(list, fnCols))
}
