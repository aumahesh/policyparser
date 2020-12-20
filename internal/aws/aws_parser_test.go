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
	log.SetLevel(log.DebugLevel)

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
	assert.EqualValues(t, "arn:aws:iam::<.*>:role/aws-reserved/sso.amazonaws.com/<.*>", policies[0].Resources[0])

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
	log.SetLevel(log.DebugLevel)

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

func TestAwsParser_Parse5(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	encodedText := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ADescribeSpotFleetRequests%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3AModifySpotFleetRequest%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADescribeAlarms%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3APutMetricAlarm%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADeleteAlarms%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateServiceLinkedRole%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A%2A%3Arole%2Faws-service-role%2Fec2.application-autoscaling.amazonaws.com%2FAWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Condition%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%22StringLike%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAWSServiceName%22%3A%20%22ec2.application-autoscaling.amazonaws.com%22%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%20%0A%20%20%20%20%5D%0A%7D`
	/*
			url decoded policy:
		{
		    "Version": "2012-10-17",
		    "Statement": [
		        {
		            "Effect": "Allow",
		            "Action": [
		                "ec2:DescribeSpotFleetRequests",
		                "ec2:ModifySpotFleetRequest"
		            ],
		            "Resource": [
		                "*"
		            ]
		        },
		        {
		            "Effect": "Allow",
		            "Action": [
		                "cloudwatch:DescribeAlarms",
		                "cloudwatch:PutMetricAlarm",
		                "cloudwatch:DeleteAlarms"
		            ],
		            "Resource": [
		                "*"
		            ]
		        },
		        {
		          "Effect": "Allow",
		          "Action": "iam:CreateServiceLinkedRole",
		          "Resource": "arn:aws:iam::*:role/aws-service-role/ec2.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest",
		          "Condition": {
		            "StringLike": {
		              "iam:AWSServiceName": "ec2.application-autoscaling.amazonaws.com"
		            }
		          }
		        }
		    ]
		}
	*/

	a, err := NewAwsPolicyParser(encodedText, true)
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

	assert.Len(t, policies, 3)
	if len(policies) != 3 {
		t.FailNow()
	}

	actions := []int{2, 3, 1}
	resources := []int{1, 1, 1}
	conditions := []int{0, 0, 1}

	for index, p := range policies {
		assert.Len(t, p.Actions, actions[index])
		assert.Len(t, p.Resources, resources[index])
		assert.Len(t, p.Condition, conditions[index])
	}
}

func TestAwsParser_Parse6(t *testing.T) {
	encodedText := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3ADescribeSpotFleetRequests%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22ec2%3AModifySpotFleetRequest%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADescribeAlarms%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3APutMetricAlarm%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22cloudwatch%3ADeleteAlarms%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%2A%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22iam%3ACreateServiceLinkedRole%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22arn%3Aaws%3Aiam%3A%3A%2A%3Arole%2Faws-service-role%2Fec2.application-autoscaling.amazonaws.com%2FAWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest%22%2C%20%0A%20%20%20%20%20%20%20%20%20%20%22Condition%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%22StringLike%22%3A%20%7B%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22iam%3AAWSServiceName%22%3A%20%22ec2.application-autoscaling.amazonaws.com%22%20%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%20%0A%20%20%20%20%5D%0A%7D`

	a, err := NewAwsPolicyParser(encodedText, true)
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

	assert.Len(t, policies, 3)
	if len(policies) != 3 {
		t.FailNow()
	}

	actions := []int{2, 3, 1}
	resources := []int{1, 1, 1}
	conditions := []int{0, 0, 1}

	for index, p := range policies {
		assert.Len(t, p.Actions, actions[index])
		assert.Len(t, p.Resources, resources[index])
		assert.Len(t, p.Condition, conditions[index])
	}
}
