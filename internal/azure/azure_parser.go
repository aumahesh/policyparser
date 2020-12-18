package azure

type AzureParser struct {
	policyFile string
	urlEscaped bool
	outputFile string
}

func NewAzurePolicyParser(pf string, escaped bool, of string) (*AzureParser, error) {
	return &AzureParser{
		policyFile: pf,
		urlEscaped: escaped,
		outputFile: of,
	}, nil
}

func (a *AzureParser) Parse() error {
	return nil
}

func (a *AzureParser) Write() error {
	return nil
}

func (a *AzureParser) String() (string, error) {
	return "", nil
}
