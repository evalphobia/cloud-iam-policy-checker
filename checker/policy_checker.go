package checker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/evalphobia/aws-sdk-go-wrapper/config"
	"github.com/evalphobia/aws-sdk-go-wrapper/iam"
)

// PolicyChecker is struct for checking IAM policies.
type PolicyChecker struct {
	config Config
	client *iam.IAM
}

// New create *PolicyChecker from empty config.
func New() (*PolicyChecker, error) {
	return NewWithConfig(Config{})
}

// NewWithConfig create *PolicyChecker from config.Config.
func NewWithConfig(conf Config) (*PolicyChecker, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	cli, err := iam.New(config.Config{})
	if err != nil {
		return nil, err
	}

	return &PolicyChecker{
		config: conf,
		client: cli,
	}, nil
}

// hasTargetPermission checks if the statements contains target Resource/Action/Service from config.
func (c *PolicyChecker) hasTargetPermission(statements []iam.Statement) bool {
	if c.config.ShowAllPolicy {
		return true
	}

	for _, s := range statements {
		if hasTargetPermission(c.config, s) {
			return true
		}
	}
	return false
}

func (c *PolicyChecker) loggingError(template string, params ...interface{}) {
	if len(params) == 0 {
		return
	}
	if params[0] == nil {
		return
	}

	fmt.Printf("[Checker] [ERROR] %s\n", fmt.Sprintf(template, params...))
}

func (c *PolicyChecker) loggingInfo(template string, params ...interface{}) {
	fmt.Printf("[Checker] [INFO] %s\n", fmt.Sprintf(template, params...))
}

// hasTargetPermission checks if the given statement contains target permissions.
func hasTargetPermission(c Config, s iam.Statement) bool {
	if !s.IsAllow() {
		return false
	}

	svc := c.GetTargetActionServices()
	if svc.hasService() {
		return svc.HasTargetInActions(s.Action)
	}
	if containsStringInList(s.Resource, c.GetTargetResources()) {
		return true
	}
	return containsStringInList(s.Action, c.GetTargetActions())
}

// containsStringInList checks if targetString contains in the list.
func containsStringInList(list []string, substrList []string) bool {
	for _, s := range list {
		for _, substr := range substrList {
			if strings.Contains(s, substr) {
				return true
			}
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

// apply fnCols to each AwsPolicy's field and output rows data.
func toSliceForOutpout(list []*AwsPolicy, fnCols func(*AwsPolicy) []string) [][]string {
	lines := make([][]string, len(list))
	for i, p := range list {
		lines[i] = fnCols(p)
	}
	return lines
}
