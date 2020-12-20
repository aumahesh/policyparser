build: parser-fmt parser-build

test: parser-fmt parser-test

fmt: parser-fmt

clean: parser-clean

parser-build:
	echo "Compiling policyparser"
	mkdir -p bin/ && go build -o bin/parser github.com/aumahesh/policyparser/cmd

parser-test:
	echo "Running tests"
	go test github.com/aumahesh/policyparser/...

parser-fmt:
	gofmt -w .

parser-clean:
	rm -rf bin/parser


