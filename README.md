Cloud IAM Policy Checker
----

[![GoDoc][1]][2] [![License: MIT][3]][4] [![Release][5]][6] [![Build Status][7]][8] [![Go Report Card][13]][14] [![Code Climate][19]][20] [![BCH compliance][21]][22]

[1]: https://godoc.org/github.com/evalphobia/cloud-iam-policy-checker?status.svg
[2]: https://godoc.org/github.com/evalphobia/cloud-iam-policy-checker
[3]: https://img.shields.io/badge/License-MIT-blue.svg
[4]: LICENSE.md
[5]: https://img.shields.io/github/release/evalphobia/cloud-iam-policy-checker.svg
[6]: https://github.com/evalphobia/cloud-iam-policy-checker/releases/latest
[7]: https://travis-ci.org/evalphobia/cloud-iam-policy-checker.svg?branch=master
[8]: https://travis-ci.org/evalphobia/cloud-iam-policy-checker
[9]: https://coveralls.io/repos/evalphobia/cloud-iam-policy-checker/badge.svg?branch=master&service=github
[10]: https://coveralls.io/github/evalphobia/cloud-iam-policy-checker?branch=master
[11]: https://codecov.io/github/evalphobia/cloud-iam-policy-checker/coverage.svg?branch=master
[12]: https://codecov.io/github/evalphobia/cloud-iam-policy-checker?branch=master
[13]: https://goreportcard.com/badge/github.com/evalphobia/cloud-iam-policy-checker
[14]: https://goreportcard.com/report/github.com/evalphobia/cloud-iam-policy-checker
[15]: https://img.shields.io/github/downloads/evalphobia/cloud-iam-policy-checker/total.svg?maxAge=1800
[16]: https://github.com/evalphobia/cloud-iam-policy-checker/releases
[17]: https://img.shields.io/github/stars/evalphobia/cloud-iam-policy-checker.svg
[18]: https://github.com/evalphobia/cloud-iam-policy-checker/stargazers
[19]: https://codeclimate.com/github/evalphobia/cloud-iam-policy-checker/badges/gpa.svg
[20]: https://codeclimate.com/github/evalphobia/cloud-iam-policy-checker
[21]: https://bettercodehub.com/edge/badge/evalphobia/cloud-iam-policy-checker?branch=master
[22]: https://bettercodehub.com/


`cloud-iam-policy-checker` is a tool to check IAM policy on AWS.


# What's for?

This tool checks IAM policy and create CSV list of policies having broader permissions and attached users.
You can use this to improve security and audit report.


# Quick Usage

At first, install golang.
And gets dependensies.

```bash
$ make init
$ make dep
```

## Local command

Build first,

```bash
$ make build-local
```

Then executes,

```bash
$ bin/cloud-iam-policy-checker
```

After a while, `output.csv` will be created in the directory.

```bash
$ cat output.csv

policy_arn,policy_name,policy_action,policy_resource_action,attached_user,attached_group,attached_group_user,attached_all_user,attached_role
arn:aws:iam::012345678901:policy/CloudFormationFullAccess,CloudFormationFullAccess,cloudformation:*,"{
  ""actions"": [
    ""cloudformation:*""
  ],
  ""resources"": [
    ""*""
  ]
}",,developers,"foo
bar","foo
bar",
```


# Environment variables

|Name|Description|
|:--|:--|
| `AWS_ACCESS_KEY_ID` | AWS access key id |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key |
| `POLICY_CHECKER_OUTPUT_FILE` | Output file name (default: `output.csv`) |
| `POLICY_CHECKER_TARGET_RESOURCE` | Target resource ARN (default: `*`) |
| `POLICY_CHECKER_TARGET_ACTION` | Target action (default: `*`) |
| `POLICY_CHECKER_TARGET_ACTION_SERVICE` | Target service in action. If set this, then target resource and action does not be used. You can set multiple services using comma. (e.g. `ec2,s3,kms`) |


# AWS Permissions

This program needs these permissions.

|Action|
|:--|
| `iam:GetGroup` |
| `iam:GetPolicyVersion` |
| `iam:ListAttachedPolicies` |
| `iam:ListEntitiesForPolicy` |
