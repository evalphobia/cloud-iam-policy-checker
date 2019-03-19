package main

import (
	"github.com/mkideal/cli"

	"github.com/evalphobia/cloud-iam-policy-checker/checker"
)

// inlinePolicy command
type inlinePolicyT struct {
	cli.Helper
	Output              string `cli:"o,output" usage:"output CSV/TSV file path (e.g. --output='./output.csv')" dft:"inline_policy.csv"`
	TargetResource      string `cli:"r,resource" usage:"filtering rule for resources; space separated (e.g. --resource='arn:aws:s3:* arn:aws:sns:*')"`
	TargetAction        string `cli:"a,action" usage:"filtering rule for action; space separated (e.g. --action='S3:Get* SNS:*')"`
	TargetActionService string `cli:"s,service" usage:"filtering rule for action services; space separated (e.g. --service='s3 sns ecr')"`
	AllPolicy           bool   `cli:"all" usage:"do not use filtering and output all inline policy"`
}

var inlinePolicy = &cli.Command{
	Name: "inline_policy",
	Desc: "Get list of inline policies from User/Group/Role",
	Argv: func() interface{} { return new(inlinePolicyT) },
	Fn:   execInlinePolicy,
}

func execInlinePolicy(ctx *cli.Context) error {
	argv := ctx.Argv().(*inlinePolicyT)

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

	return c.CheckInlinePolicies()
}
