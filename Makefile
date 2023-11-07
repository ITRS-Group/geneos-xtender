BIN_NAME=xtender
export DOCKER_BUILDKIT=1

all: target/release/${BIN_NAME}
.PHONY: target/release/${BIN_NAME}

target/release/${BIN_NAME}:
	@docker build --platform linux/amd64 --target bin --output . .

test:
	act workflow_dispatch --container-architecture linux/amd64 --platform linux/amd64 --no-cache-server -W .github/workflows/test.yaml

bats:
	act workflow_dispatch --container-architecture linux/amd64 --platform linux/amd64 -j build_and_test --no-cache-server -W .github/workflows/test.yaml
