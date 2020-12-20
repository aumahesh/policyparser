package parser

import (
	"fmt"

	"github.com/aumahesh/policyparser/internal/aws"
	"github.com/aumahesh/policyparser/internal/azure"
	"github.com/aumahesh/policyparser/internal/gcp"
	"github.com/aumahesh/policyparser/pkg/policy"
)

const (
	Aws   = "aws"
	Azure = "azure"
	Gcp   = "gcp"
)

type Parser interface {
	Parse() error
	GetPolicy() ([]*policy.Policy, error)
}

func NewParser(p, policyText string, escaped bool) (Parser, error) {
	switch p {
	case Aws:
		return aws.NewAwsPolicyParser(policyText, escaped)
	case Azure:
		return azure.NewAzurePolicyParser(policyText, escaped)
	case Gcp:
		return gcp.NewGcpPolicyParser(policyText, escaped)
	}
	return nil, fmt.Errorf("%s is not a supported cloud provider", p)
}
