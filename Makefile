BIN_NAME=xtender
export DOCKER_BUILDKIT=1

all: target/release/${BIN_NAME}
.PHONY: target/release/${BIN_NAME}

target/release/${BIN_NAME}:
	@docker build --target bin --output . .

bats:
	./scripts/build_and_run_bats.sh $(image)
