package checker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/evalphobia/aws-sdk-go-wrapper/config"
	"github.com/evalphobia/aws-sdk-go-wrapper/iam"
)

// AwsPolicyChecker is struct for checking IAM policies.
type AwsPolicyChecker struct {
	config Config
	client *iam.IAM
}

// New returns initialized *AwsPolicyChecker with AWS client.
func New() (*AwsPolicyChecker, error) {
	cli, err := iam.New(config.Config{})
	if err != nil {
		return nil, err
	}

	return &AwsPolicyChecker{
		client: cli,
	}, nil
}

// CheckPolicies fetches policy list and check the permissions.
func (c *AwsPolicyChecker) CheckPolicies() error {
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
	return c.savePolicyList(targetList)
}

// fetchAwsPolicies executes iam:ListAttachedPolicies.
func (c *AwsPolicyChecker) fetchAwsPolicies() ([]iam.Policy, error) {
	c.loggingInfo("invoking `fetchAwsPolicies` ...")

	list, err := c.client.ListAttachedPolicies()
	c.loggingError("Func:[ListAttachedPolicies] Error:[%s]", err)
	return list, err
}

// fetchTargetPolicyWithBody fetches policy body and create a list of the policies which contains target permissions.
func (c *AwsPolicyChecker) fetchTargetPolicyWithBody(list []iam.Policy) []*AwsPolicy {
	c.loggingInfo("invoking `fetchTargetPolicyWithBody` ...")

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

		isTarget := false
		for _, s := range policy.Statement {
			if hasTargetPermission(c.config, s) {
				isTarget = true
				break
			}
		}
		if isTarget {
			ap := AwsPolicy{
				ARN:        p.ARN,
				PolicyName: p.PolicyName,
			}
			ap.SetPolicy(policy)
			targetList = append(targetList, &ap)
		}
	}

	return targetList
}

// fetchAndSetEntity fetches PolicyEntity and sets them into *AwsPolicy.
func (c *AwsPolicyChecker) fetchAndSetEntity(list []*AwsPolicy) {
	c.loggingInfo("invoking `fetchAndSetEntity` ...")

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
func (c *AwsPolicyChecker) fillMembersFromGroup(list []*AwsPolicy) {
	c.loggingInfo("invoking `fetchAndSetEntity` ...")

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

// savePolicyList saves policy list results to local file.
func (c *AwsPolicyChecker) savePolicyList(list []*AwsPolicy) error {
	c.loggingInfo("invoking `savePolicyList` ...")

	f, err := NewFileHandler(c.config.GetOutputFile())
	if err != nil {
		return err
	}

	return f.WriteAll(defaultHeaders, toSliceForOutpout(list))
}

func (c *AwsPolicyChecker) loggingError(template string, params ...interface{}) {
	if len(params) == 0 {
		return
	}
	if params[0] == nil {
		return
	}

	fmt.Printf("[Checker] [ERROR] %s\n", fmt.Sprintf(template, params...))
}

func (c *AwsPolicyChecker) loggingInfo(template string, params ...interface{}) {
	fmt.Printf("[Checker] [INFO] %s\n", fmt.Sprintf(template, params...))
}

// hasTargetPermission checks if the given statement contains target permissions.
func hasTargetPermission(c Config, s iam.Statement) bool {
	if !s.IsAllow() {
		return false
	}

	svc := c.GetTargetActionService()
	if svc.hasService() {
		return svc.HasTargetInActions(s.Action)
	}
	if containsStringInList(s.Resource, c.GetTargetResource()) {
		return true
	}
	return containsStringInList(s.Action, c.GetTargetAction())
}

// containsStringInList checks if targetString contains in the list.
func containsStringInList(list []string, targetString string) bool {
	for _, s := range list {
		if strings.Contains(s, targetString) {
			return true
		}
	}
	return false
}

// uniqueAndSort removes duplicates and sorts order for string slice.
func uniqueAndSort(list []string) {
	// unique
	m := make(map[string]struct{}, len(list))
	for _, v := range list {
		m[v] = struct{}{}
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	// sort
	sort.Strings(keys)
}
