package checker

import (
	"strings"

	"github.com/evalphobia/aws-sdk-go-wrapper/iam"
)

// CheckPolicies fetches policy list and check the permissions.
func (c *PolicyChecker) CheckPolicies() error {
	if err := checkIsDir(c.config.GetOutputFile()); err != nil {
		return err
	}

	list, err := c.fetchAwsPolicies()
	if err != nil {
		return err
	}

	targetList := c.fetchTargetPolicyWithBody(list)
	c.fetchAndSetEntity(targetList)
	c.fillMembersFromGroup(targetList)
	return c.savePolicies(targetList)
}

// fetchAwsPolicies executes iam:ListAttachedPolicies.
func (c *PolicyChecker) fetchAwsPolicies() ([]iam.Policy, error) {
	c.loggingInfo("invoking `fetchAwsPolicies` ...")

	list, err := c.client.ListAttachedPolicies()
	c.loggingError("Func:[ListAttachedPolicies] Error:[%s]", err)
	return list, err
}

// fetchTargetPolicyWithBody fetches policy body and create a list of the policies which contains target permissions.
func (c *PolicyChecker) fetchTargetPolicyWithBody(list []iam.Policy) []*AwsPolicy {
	c.loggingInfo("invoking `fetchTargetPolicyWithBody` size:[%d] ...", len(list))

	cli := c.client
	targetList := make([]*AwsPolicy, 0, len(list))
	for _, p := range list {
		v, err := cli.GetPolicyVersion(p.ARN, p.VersionID)
		if err != nil {
			c.loggingError("Func:[GetPolicyVersion] Error:[%s], ARN:[%s]", err, p.ARN)
			continue
		}
		policy, err := iam.NewPolicyDocumentFromDocument(*v.Document)
		if err != nil {
			c.loggingError("Func:[NewPolicyFromDocument] Error:[%s], ARN:[%s]", err, p.ARN)
			continue
		}

		// filter policies by Resource/Action/Service from config.
		if !c.hasTargetPermission(policy.Statement) {
			continue
		}

		ap := AwsPolicy{
			ARN:        p.ARN,
			PolicyName: p.PolicyName,
		}
		ap.SetPolicy(policy)
		targetList = append(targetList, &ap)
	}

	return targetList
}

// fetchAndSetEntity fetches PolicyEntity and sets them into *AwsPolicy.
func (c *PolicyChecker) fetchAndSetEntity(list []*AwsPolicy) {
	c.loggingInfo("invoking `fetchAndSetEntity` size:[%d] ...", len(list))

	cli := c.client
	for _, p := range list {
		entList, err := cli.ListEntitiesForPolicy(p.ARN)
		if err != nil {
			c.loggingError("Func:[NewPolicyFromDocument] Error:[%s], ARN:[%s]", err, p.ARN)
			continue
		}
		p.SetEntityList(entList)
	}
}

// fillMembersFromGroup fetches users of the group and sets them into *AwsPolicy
func (c *PolicyChecker) fillMembersFromGroup(list []*AwsPolicy) {
	c.loggingInfo("invoking `fetchAndSetEntity` size:[%d] ...", len(list))

	cli := c.client
	groupMembers := make(map[string][]string)
	for _, p := range list {
		for _, g := range p.AttachedGroups {
			groupMembers[g.Name] = nil
		}
	}

	for key := range groupMembers {
		o, err := cli.GetGroup(key)
		if err != nil {
			c.loggingError("Func:[GetGroup] Error:[%s], Group:[%s]", err, key)
			continue
		}

		users := make([]string, len(o.Users))
		for i, u := range o.Users {
			users[i] = *u.UserName
		}
		groupMembers[key] = users
	}

	for _, p := range list {
		for i, g := range p.AttachedGroups {
			u, ok := groupMembers[g.Name]
			if !ok {
				continue
			}
			g.Users = u
			p.AttachedGroups[i] = g
			p.AttachedGroupUsers = append(p.AttachedGroupUsers, u...)
		}
		uniqueAndSort(p.AttachedGroupUsers)

		p.AttachedAllUsers = append(p.AttachedAllUsers, p.AttachedGroupUsers...)
		uniqueAndSort(p.AttachedAllUsers)
	}
}

// savePolicies saves policy list results to local file.
func (c *PolicyChecker) savePolicies(list []*AwsPolicy) error {
	c.loggingInfo("invoking `savePolicies` size:[%d] ...", len(list))

	f, err := NewFileHandler(c.config.GetOutputFile())
	if err != nil {
		return err
	}

	// CSV headers
	headers := []string{
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

	// CSV row
	fnCols := func(p *AwsPolicy) []string {
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

	return f.WriteAll(headers, toSliceForOutpout(list, fnCols))
}
