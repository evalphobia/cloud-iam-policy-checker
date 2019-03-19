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

Then, create binary file.

```bash
$ make build-local
```

```bash
$ bin/cloud-iam-policy-checker -h

Commands:

  help            show help
  policy          Get list of IAM policies
  inline_policy   Get list of inline policies from User/Group/Role
```



## Subcommands

### policy

`policy` command retrieves IAM policies including the statements and attached user/group/role.


```bash
$ bin/cloud-iam-policy-checker policy -h

Get list of IAM policies

Options:

  -h, --help                  display help information
  -o, --output[=policy.csv]   output CSV/TSV file path (e.g. --output='./output.csv')
  -r, --resource              filtering rule for resources; space separated (e.g. --resource='arn:aws:s3:* arn:aws:sns:*')
  -a, --action                filtering rule for action; space separated (e.g. --action='S3:Get* SNS:* Delete')
  -s, --service               filtering rule for action services; space separated (e.g. --service='s3 sns ecr')
      --all                   do not use filtering and output all inline policy
```

For example, if you want all of the IAM policies,

```bash
$ bin/cloud-iam-policy-checker policy --all

[Checker] [INFO] invoking `fetchAwsPolicies` ...
[Checker] [INFO] invoking `fetchTargetPolicyWithBody` size:[1] ...
[Checker] [INFO] invoking `fetchAndSetEntity` size:[1] ...
[Checker] [INFO] invoking `fetchAndSetEntity` size:[1] ...
[Checker] [INFO] invoking `savePolicies` size:[1] ...
```

After a while, `policy.csv` will be created in the directory.

```bash
$ cat policy.csv

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


### inline_policy

`inline_policy` command retrieves inline policies from user/group/role.


```bash
$ bin/cloud-iam-policy-checker inline_policy -h

Get list of inline policies from User/Group/Role

Options:

  -h, --help                         display help information
  -o, --output[=inline_policy.csv]   output CSV/TSV file path (e.g. --output='./output.csv')
  -r, --resource                     filtering rule for resources; space separated (e.g. --resource='arn:aws:s3:* arn:aws:sns:*')
  -a, --action                       filtering rule for action; space separated (e.g. --action='S3:Get* SNS:*')
  -s, --service                      filtering rule for action services; space separated (e.g. --service='s3 sns ecr')
      --all                          do not use filtering and output all inline policy
```

For example, if you want the inline policies including `Create` and `Delete` type action,

```bash
$ bin/cloud-iam-policy-checker inline_policy -a "Create Delete"

[Checker] [INFO] invoking `fetchUsers` ...
[Checker] [INFO] invoking `fetchInlinePolicyFromUsers` size:[1] ...
[Checker] [INFO] invoking `fetchGroups` ...
[Checker] [INFO] invoking `fetchInlinePolicyFromGroups` size:[1] ...
[Checker] [INFO] invoking `fetchRoles` ...
[Checker] [INFO] invoking `fetchInlinePolicyFromRoles` size:[1] ...
[Checker] [INFO] invoking `saveInlinePolicies` size:[1] ...
```

After a while, `inline_policy.csv` will be created in the directory.

```bash
$ cat inline_policy.csv

entity_type,entity_name,policy_name,policy_action,policy_resource_action
user,sns-user,sns-publush,SNS:Publish,"{
  ""actions"": [
    ""SQS:Delete*""
  ],
  ""resources"": [
    ""arn:aws:sns:ap-northeast-1:012345678901:*""
  ]
}"
```


# Environment variables

|Name|Description|
|:--|:--|
| `AWS_ACCESS_KEY_ID` | AWS access key id |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key |
| `POLICY_CHECKER_OUTPUT_FILE` | Output file name (default: `output.csv`) |
| `POLICY_CHECKER_TARGET_RESOURCE` | Target resource ARN. You can set multiple actions using space. (e.g. `arn:aws:sns:* arn:aws:sqs:*`) |
| `POLICY_CHECKER_TARGET_ACTION` | Target action. You can set multiple actions using space. (e.g. `Get List Describe`) |
| `POLICY_CHECKER_TARGET_ACTION_SERVICE` | Target service in action. If set this, then target resource and action does not be used. You can set multiple services using space. (e.g. `ec2 s3 kms`) |


# AWS Permissions

This program needs these permissions.

|Action|
|:--|
| `iam:GetGroup` |
| `iam:GetPolicyVersion` |
| `iam:GetUserPolicyDocument` |
| `iam:GetGroupPolicyDocument` |
| `iam:GetRolePolicyDocument` |
| `iam:ListAttachedPolicies` |
| `iam:ListEntitiesForPolicy` |
| `iam:ListGroups` |
| `iam:ListGroupPolicies` |
| `iam:ListUsers` |
| `iam:ListUserPolicies` |
| `iam:ListRoles` |
| `iam:ListRolePolicies` |
