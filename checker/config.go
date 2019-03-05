package checker

import (
	"os"
	"strings"
)

const (
	defaultOutputFile     = "output.csv"
	defaultTargetResource = "*"
	defaultTargetAction   = "*"

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
	OutputFile           string
	TargetResource       string
	TargetAction         string
	TargetActionServices []string

	targetService *TargetService
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

// GetTargetResource gets filter rule for policy resource.
func (c Config) GetTargetResource() string {
	switch {
	case c.TargetResource != "":
		return c.TargetResource
	case envValueTargetResource != "":
		return envValueTargetResource
	default:
		return defaultTargetResource
	}
}

// GetTargetAction gets filter rule for policy action.
func (c Config) GetTargetAction() string {
	switch {
	case c.TargetAction != "":
		return c.TargetAction
	case envValueTargetAction != "":
		return envValueTargetAction
	default:
		return defaultTargetAction
	}
}

// GetTargetActionService gets filter rule for services in policy action.
func (c *Config) GetTargetActionService() *TargetService {
	if c.targetService != nil {
		return c.targetService
	}

	var svc TargetService
	switch {
	case len(c.TargetActionServices) != 0:
		svc = newTargetService(c.TargetActionServices)
	case envValueTargetActionService != "":
		svc = newTargetService(strings.Split(envValueTargetActionService, ","))
	default:
		return &TargetService{}
	}

	c.targetService = &svc
	return c.targetService
}
