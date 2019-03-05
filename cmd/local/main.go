package main

import (
	"github.com/evalphobia/cloud-iam-policy-checker/checker"
)

func main() {
	c, err := checker.New()
	if err != nil {
		panic(err)
	}

	err = c.CheckPolicies()
	if err != nil {
		panic(err)
	}
}
