package checker

import (
	"errors"
	"os"
	"strings"
)

const (
	defaultSeparator  = " "
	defaultOutputFile = "output.csv"

	// enviroment parameters
	envKeyOutputFile     = "POLICY_CHECKER_OUTPUT_FILE"
	envKeyTargetResource = "POLICY_CHECKER_TARGET_RESOURCE"
	envKeyTargetAction   = "POLICY_CHECKER_TARGET_ACTION"
	// service name. use comma for multiple services. (ref: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html)
	envKeyTargetActionService = "POLICY_CHECKER_TARGET_ACTION_SERVICE"
)

var (
	envValueOutputFile          = os.Getenv(envKeyOutputFile)
	envValueTargetResource      = os.Getenv(envKeyTargetResource)
	envValueTargetAction        = os.Getenv(envKeyTargetAction)
	envValueTargetActionService = os.Getenv(envKeyTargetActionService)
)

// Config contains settings.
type Config struct {
	OutputFile          string
	TargetResource      string // space separated
	TargetAction        string // space separated
	TargetActionService string // space separated
	ShowAllPolicy       bool

	targetResources []string
	targetActions   []string
	targetServices  *TargetService
}

// Validate validates config has valid rules or not.
func (c Config) Validate() error {
	switch {
	case c.ShowAllPolicy,
		c.TargetResource != "",
		c.TargetAction != "",
		c.TargetActionService != "":
		return nil
	}
	return errors.New("Config does not contain valid rules")
}

// GetOutputFile gets output file name.
func (c Config) GetOutputFile() string {
	switch {
	case c.OutputFile != "":
		return c.OutputFile
	case envValueOutputFile != "":
		return envValueOutputFile
	default:
		return defaultOutputFile
	}
}

// GetTargetResources gets filter rule for policy resource.
func (c *Config) GetTargetResources() []string {
	if c.targetResources != nil {
		return c.targetResources
	}

	c.targetResources = toStringList(c.TargetResource, envValueTargetResource)
	return c.targetResources
}

// GetTargetActions gets filter rule for policy action.
func (c *Config) GetTargetActions() []string {
	if c.targetActions != nil {
		return c.targetActions
	}

	c.targetActions = toStringList(c.TargetAction, envValueTargetAction)
	return c.targetActions
}

// GetTargetActionServices gets filter rule for services in policy action.
func (c *Config) GetTargetActionServices() *TargetService {
	if c.targetServices != nil {
		return c.targetServices
	}

	list := toStringList(c.TargetActionService, envValueTargetActionService)
	if len(list) == 0 {
		return &TargetService{}
	}

	svc := newTargetService(list)
	c.targetServices = &svc
	return c.targetServices
}

func toStringList(inputs ...string) []string {
	result := make([]string, 0)

	var list []string
	for _, input := range inputs {
		if input == "" {
			continue
		}

		list = strings.Split(input, defaultSeparator)
		break
	}

	// trim vervose spaces
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		result = append(result, s)
	}
	return result
}
