package main

import (
	"github.com/mkideal/cli"

	"github.com/evalphobia/cloud-iam-policy-checker/checker"
)

// policy command
type policyT struct {
	cli.Helper
	Output              string `cli:"o,output" usage:"output CSV/TSV file path (e.g. --output='./output.csv')" dft:"policy.csv"`
	TargetResource      string `cli:"r,resource" usage:"filtering rule for resources; space separated (e.g. --resource='arn:aws:s3:* arn:aws:sns:*')"`
	TargetAction        string `cli:"a,action" usage:"filtering rule for action; space separated (e.g. --action='S3:Get* SNS:*')"`
	TargetActionService string `cli:"s,service" usage:"filtering rule for action services; space separated (e.g. --service='s3 sns ecr')"`
	AllPolicy           bool   `cli:"all" usage:"do not use filtering and output all inline policy"`
}

var policy = &cli.Command{
	Name: "policy",
	Desc: "Get list of IAM policies",
	Argv: func() interface{} { return new(policyT) },
	Fn:   execPolicy,
}

func execPolicy(ctx *cli.Context) error {
	argv := ctx.Argv().(*policyT)

	c, err := checker.NewWithConfig(checker.Config{
		OutputFile:          argv.Output,
		TargetResource:      argv.TargetResource,
		TargetAction:        argv.TargetAction,
		TargetActionService: argv.TargetActionService,
		ShowAllPolicy:       argv.AllPolicy,
	})
	if err != nil {
		return err
	}

	return c.CheckPolicies()
}
