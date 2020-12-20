package aws

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestAwsParser_Parse(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	policyText := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "iam:CreateUser",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["*"],
      "Resource": "*"
    }
  ]
}`
	t.Logf("\n%s", policyText)
	a, err := NewAwsPolicyParser(policyText, false)
	assert.Nil(t, err)
	if err != nil {
		t.FailNow()
	}

	err = a.Parse()
	assert.Nil(t, err)

	policies, err := a.GetPolicy()
	assert.Nil(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	assert.Len(t, policies, 2)
	if len(policies) != 2 {
		t.FailNow()
	}
	assert.False(t, policies[0].Allowed)
	assert.Len(t, policies[0].Subjects, 0)
	assert.Len(t, policies[0].NotSubjects, 0)
	assert.Len(t, policies[0].NotActions, 0)
	assert.Len(t, policies[0].NotResources, 0)
	assert.Len(t, policies[0].Actions, 1)
	assert.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
	assert.Len(t, policies[0].Resources, 1)
	assert.EqualValues(t, "<.*>", policies[0].Resources[0])

	assert.True(t, policies[1].Allowed)
	assert.Len(t, policies[1].Subjects, 0)
	assert.Len(t, policies[1].NotSubjects, 0)
	assert.Len(t, policies[1].NotActions, 0)
	assert.Len(t, policies[1].NotResources, 0)
	assert.Len(t, policies[1].Actions, 1)
	assert.EqualValues(t, "<.*>", policies[1].Actions[0])
	assert.Len(t, policies[1].Resources, 1)
	assert.EqualValues(t, "<.*>", policies[1].Resources[0])
}

func TestAwsParser_Parse2(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	policyText := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:CreateUser", "iam:RemoveUser"],
      "Resource": "*"
    }
  ]
}`
	t.Logf("\n%s", policyText)
	a, err := NewAwsPolicyParser(policyText, false)
	assert.Nil(t, err)
	if err != nil {
		t.FailNow()
	}

	err = a.Parse()
	assert.Nil(t, err)

	policies, err := a.GetPolicy()
	assert.Nil(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	assert.Len(t, policies, 1)
	if len(policies) != 1 {
		t.FailNow()
	}
	assert.True(t, policies[0].Allowed)
	assert.Len(t, policies[0].Subjects, 0)
	assert.Len(t, policies[0].NotSubjects, 0)
	assert.Len(t, policies[0].NotActions, 0)
	assert.Len(t, policies[0].NotResources, 0)
	assert.Len(t, policies[0].Actions, 2)
	assert.EqualValues(t, "iam:CreateUser", policies[0].Actions[0])
	assert.EqualValues(t, "iam:RemoveUser", policies[0].Actions[1])
	assert.Len(t, policies[0].Resources, 1)
	assert.EqualValues(t, "<.*>", policies[0].Resources[0])
}

func TestAwsParser_Parse3(t *testing.T) {
	policyText := `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMRoleProvisioningActions",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": [
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgMasterAccountId": "${aws:PrincipalAccount}"
        }
      }
    }
  ]
}`

	t.Logf("\n%s", policyText)
	a, err := NewAwsPolicyParser(policyText, false)
	assert.Nil(t, err)
	if err != nil {
		t.FailNow()
	}

	err = a.Parse()
	assert.Nil(t, err)

	policies, err := a.GetPolicy()
	assert.Nil(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	assert.Len(t, policies, 1)
	if len(policies) != 1 {
		t.FailNow()
	}
	assert.True(t, policies[0].Allowed)
	assert.Len(t, policies[0].Subjects, 0)
	assert.Len(t, policies[0].NotSubjects, 0)
	assert.Len(t, policies[0].NotActions, 0)
	assert.Len(t, policies[0].NotResources, 0)
	assert.Len(t, policies[0].Actions, 6)
	assert.EqualValues(t, "iam:AttachRolePolicy", policies[0].Actions[0])
	assert.EqualValues(t, "iam:CreateRole", policies[0].Actions[1])
	assert.EqualValues(t, "iam:PutRolePolicy", policies[0].Actions[2])
	assert.EqualValues(t, "iam:UpdateRole", policies[0].Actions[3])
	assert.EqualValues(t, "iam:UpdateRoleDescription", policies[0].Actions[4])
	assert.EqualValues(t, "iam:UpdateAssumeRolePolicy", policies[0].Actions[5])
	assert.Len(t, policies[0].Resources, 1)
	assert.EqualValues(t, "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*", policies[0].Resources[0])

	assert.Len(t, policies[0].Condition, 1)
	if len(policies[0].Condition) != 1 {
		t.FailNow()
	}

	assert.EqualValues(t, "StringNotEquals", policies[0].Condition[0].Operation)
	assert.EqualValues(t, "aws:PrincipalOrgMasterAccountId", policies[0].Condition[0].Key)
	assert.Len(t, policies[0].Condition[0].Value, 1)
	assert.EqualValues(t, "string", policies[0].Condition[0].Type)
	vs := policies[0].Condition[0].Value.([]string)
	assert.EqualValues(t, "${aws:PrincipalAccount}", vs[0])
}

func TestAwsParser_Parse4(t *testing.T) {
	policyText := `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "us-west-2:7e9abc23-035e-49e7-a54a-2f850581930c"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}`

	t.Logf("\n%s", policyText)
	a, err := NewAwsPolicyParser(policyText, false)
	assert.Nil(t, err)
	if err != nil {
		t.FailNow()
	}

	err = a.Parse()
	assert.Nil(t, err)

	policies, err := a.GetPolicy()
	assert.Nil(t, err)

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}

	assert.Len(t, policies, 1)
	if len(policies) != 1 {
		t.FailNow()
	}
	assert.True(t, policies[0].Allowed)
	assert.Len(t, policies[0].Subjects, 1)
	assert.EqualValues(t, "cognito-identity.amazonaws.com", policies[0].Subjects[0])
	assert.Len(t, policies[0].NotSubjects, 0)
	assert.Len(t, policies[0].NotActions, 0)
	assert.Len(t, policies[0].Resources, 0)
	assert.Len(t, policies[0].NotResources, 0)
	assert.Len(t, policies[0].Actions, 1)
	assert.EqualValues(t, "sts:AssumeRoleWithWebIdentity", policies[0].Actions[0])

	assert.Len(t, policies[0].Condition, 2)
	if len(policies[0].Condition) != 2 {
		t.FailNow()
	}

	assert.EqualValues(t, "StringEquals", policies[0].Condition[0].Operation)
	assert.EqualValues(t, "cognito-identity.amazonaws.com:aud", policies[0].Condition[0].Key)
	assert.Len(t, policies[0].Condition[0].Value, 1)
	assert.EqualValues(t, "string", policies[0].Condition[0].Type)
	vs := policies[0].Condition[0].Value.([]string)
	assert.EqualValues(t, "us-west-2:7e9abc23-035e-49e7-a54a-2f850581930c", vs[0])

	assert.EqualValues(t, "ForAnyValue:StringLike", policies[0].Condition[1].Operation)
	assert.EqualValues(t, "cognito-identity.amazonaws.com:amr", policies[0].Condition[1].Key)
	assert.Len(t, policies[0].Condition[1].Value, 1)
	assert.EqualValues(t, "string", policies[0].Condition[1].Type)
	vs = policies[0].Condition[1].Value.([]string)
	assert.EqualValues(t, "authenticated", vs[0])
}
