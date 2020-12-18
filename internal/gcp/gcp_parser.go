package gcp

type GcpParser struct {
	policyFile string
	urlEscaped bool
	outputFile string
}

func NewGcpPolicyParser(pf string, escaped bool, of string) (*GcpParser, error) {
	return &GcpParser{
		policyFile: pf,
		urlEscaped: escaped,
		outputFile: of,
	}, nil
}

func (a *GcpParser) Parse() error {
	return nil
}

func (a *GcpParser) Write() error {
	return nil
}

func (a *GcpParser) String() (string, error) {
	return "", nil
}
