.PHONY: sandbox sandbox-inspect sandbox-direct sandbox-clean

sandbox:
	scripts/sandbox.sh up

sandbox-inspect:
	scripts/sandbox.sh inspect

sandbox-direct:
	scripts/sandbox.sh direct

sandbox-clean:
	scripts/sandbox.sh clean
