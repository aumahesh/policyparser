build: parser-build

test: parser-test

clean: parser-clean

parser-build:
	echo "Compiling agbuilder"
	mkdir -p bin/ && go build -o bin/parser github.com/aumahesh/policyparser/cmd

parser-test:
	echo "Running tests"
	go test github.com/aumahesh/policyparser/...

parser-clean:
	rm -rf bin/parser


