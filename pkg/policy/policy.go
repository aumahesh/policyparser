package policy

type Policy struct {
	Id           string      // policy Id
	Version      string      // policy Version
	Subjects     []string    // list of subjects included
	NotSubjects  []string    // list of subjects excluded
	Resources    []string    // list of resources included
	NotResources []string    // list of resources excluded
	Actions      []string    // list of actions included
	NotActions   []string    // list of actions excluded
	Allowed      bool        // effect of a policy match
	Condition    []Condition // map key is the operator
}

type Condition struct {
	Operation string      // condition operator
	Key       string      // name of the parameter that should match the value
	Value     interface{} // is a list of either string, int64 or bool
	Type      string      // string, int64, bool
}
