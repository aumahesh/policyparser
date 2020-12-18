package parser

import (
	"fmt"

	"github.com/aumahesh/policyparser/internal/aws"
	"github.com/aumahesh/policyparser/internal/azure"
	"github.com/aumahesh/policyparser/internal/gcp"
)

const (
	Aws   = "aws"
	Azure = "azure"
	Gcp   = "gcp"
)

type Parser interface {
	Parse() error
	Write() error
	String() (string, error)
}

func NewParser(p, pf string, escaped bool, of string) (Parser, error) {
	switch p {
	case Aws:
		return aws.NewAwsPolicyParser(pf, escaped, of)
	case Azure:
		return azure.NewAzurePolicyParser(pf, escaped, of)
	case Gcp:
		return gcp.NewGcpPolicyParser(pf, escaped, of)
	}
	return nil, fmt.Errorf("%s is not a supported cloud provider", p)
}
