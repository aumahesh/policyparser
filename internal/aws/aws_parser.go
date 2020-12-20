package aws

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/alecthomas/repr"
	log "github.com/sirupsen/logrus"

	"github.com/aumahesh/policyparser/pkg/policy"
)

type AwsParser struct {
	policyText string
	awsPolicy  *AwsPolicy
	policies   []*policy.Policy
	parsed     bool
	error      error
}

func NewAwsPolicyParser(policyText string, escaped bool) (*AwsParser, error) {
	var err error
	pt := policyText
	if escaped {
		pt, err = url.QueryUnescape(policyText)
		if err != nil {
			return nil, err
		}
	}
	log.Debugf("/n%s", pt)
	return &AwsParser{
		policyText: pt,
		awsPolicy:  &AwsPolicy{},
		parsed:     false,
		error:      nil,
	}, nil
}

func (a *AwsParser) Parse() error {
	parser := participle.MustBuild(a.awsPolicy,
		participle.UseLookahead(2),
	)
	err := parser.ParseString("", a.policyText, a.awsPolicy, participle.AllowTrailing(true))
	repr.Println(a.awsPolicy, repr.Hide(&lexer.Position{}))

	if err == nil {
		a.parsed = true
		a.constructPolicy()
	} else {
		perr := err.(participle.UnexpectedTokenError)
		log.Errorf("Error parsing policy: %s : %s", perr.Error(), perr.Unexpected.Pos.String())
		a.error = err
	}
	return err
}

func (a *AwsParser) GetPolicy() ([]*policy.Policy, error) {
	if a.parsed {
		return a.policies, nil
	}
	if a.error != nil {
		return nil, a.error
	}
	return nil, fmt.Errorf("did not parse")
}

func (a *AwsParser) constructPolicy() {
	if a.awsPolicy == nil {
		return
	}

	a.policies = []*policy.Policy{}

	id := StringValue(a.awsPolicy.Block.Id)
	version := StringValue(a.awsPolicy.Block.Version)

	for index, statement := range a.awsPolicy.Block.Statement {
		pol := &policy.Policy{
			Id:      fmt.Sprintf("%s:%d", id, index),
			Version: version,
		}

		for _, element := range statement.Elements {
			if element.Effect != nil {
				effect := StringValue(element.Effect)
				switch strings.ToLower(effect) {
				case "allow":
					pol.Allowed = true
				default:
					pol.Allowed = false
				}
			}
			if element.Action != nil {
				pol.Actions = a.getAnyOrList(element.Action)
			}
			if element.NotAction != nil {
				pol.NotActions = a.getAnyOrList(element.NotAction)
			}
			if element.Resource != nil {
				pol.Resources = a.getAnyOrList(element.Resource)
			}
			if element.NotResource != nil {
				pol.NotResources = a.getAnyOrList(element.NotResource)
			}
			if element.Principal != nil {
				pol.Subjects = a.getSubjects(element.Principal)
			}
			if element.NotPrincipal != nil {
				pol.NotSubjects = a.getSubjects(element.NotPrincipal)
			}
			if element.Condition != nil {
				pol.Condition = a.getCondition(element.Condition)
			}
		}

		a.policies = append(a.policies, pol)
	}
}

func (a *AwsParser) getAnyOrList(l *AnyOrList) []string {
	if l == nil {
		return []string{}
	}
	if l.Item != nil {
		if l.Item.Any {
			return []string{"<.*>"}
		}
		if l.Item.One != nil {
			vs := StringValue(l.Item.One)
			return []string{strings.ReplaceAll(vs, "*", "<.*>")}
		}
	}
	if l.List != nil {
		x := []string{}
		for _, item := range l.List {
			if item.Any {
				x = append(x, "<.*>")
			}
			if item.One != nil {
				vs := StringValue(item.One)
				x = append(x, strings.ReplaceAll(vs, "*", "<.*>"))
			}
		}
		return x
	}
	return []string{}
}

func (a *AwsParser) getSubjects(p *Principal) []string {
	if p == nil {
		return []string{}
	}
	if p.Any {
		return []string{"<.*>"}
	}
	x := []string{}
	if p.List != nil {
		for _, item := range p.List {
			if item.Aws != nil {
				x = append(x, a.getAnyOrList(item.Aws)...)
			}
			if item.Federated != nil {
				x = append(x, a.getAnyOrList(item.Federated)...)
			}
			if item.Canonical != nil {
				x = append(x, a.getAnyOrList(item.Canonical)...)
			}
			if item.Service != nil {
				x = append(x, a.getAnyOrList(item.Service)...)
			}
		}
	}

	return x
}

func (a *AwsParser) getCondition(c *Condition) []policy.Condition {
	if c == nil {
		return nil
	}

	cm := []policy.Condition{}

	for _, cc := range c.ConditionMap {
		op := StringValue(cc.Operation)
		if op == "" {
			continue
		}
		if cc.KeyValueList == nil {
			continue
		}
		ck := StringValue(cc.KeyValueList.Key)
		if ck == "" {
			continue
		}
		valType := ""
		var val interface{}
		if cc.KeyValueList.Value == nil {
			continue
		}
		if cc.KeyValueList.Value.One != nil {
			if cc.KeyValueList.Value.One.OneString != nil {
				x := []string{StringValue(cc.KeyValueList.Value.One.OneString)}
				val = x
				valType = "string"
			}
			if cc.KeyValueList.Value.One.OneNumber != nil {
				x := []int64{Int64Value(cc.KeyValueList.Value.One.OneNumber)}
				val = x
				valType = "int64"
			}
			if cc.KeyValueList.Value.One.OneNumber != nil {
				x := []bool{BoolValue(cc.KeyValueList.Value.One.OneBool)}
				val = x
				valType = "bool"
			}
		}
		if cc.KeyValueList.Value.List != nil {
			valType = ""
			mixedTypes := false
			sl := []string{}
			il := []int64{}
			bl := []bool{}
			for _, v := range cc.KeyValueList.Value.List {
				ctype := ""
				if v.OneString != nil {
					sl = append(sl, StringValue(v.OneString))
					ctype = "string"
				}
				if v.OneNumber != nil {
					il = append(il, Int64Value(v.OneNumber))
					ctype = "int64"
				}
				if v.OneNumber != nil {
					bl = append(bl, BoolValue(v.OneBool))
					ctype = "bool"
				}
				if valType == "" {
					valType = ctype
				}
				if valType != ctype {
					mixedTypes = true
					break
				}
			}
			if mixedTypes {
				continue
			}
			switch valType {
			case "string":
				val = sl
			case "int64":
				val = il
			case "bool":
				val = bl
			}
		}
		cp := policy.Condition{
			Operation: op,
			Key:       ck,
			Value:     val,
			Type:      valType,
		}

		cm = append(cm, cp)
	}

	return cm
}
