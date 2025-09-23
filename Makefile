BIN_NAME=xtender
export DOCKER_BUILDKIT=1

all: target/release/${BIN_NAME}
.PHONY: target/release/${BIN_NAME} clean

target/release/${BIN_NAME}:
	@docker build --platform linux/amd64 --target bin --output type=local,dest=target/release .
	@# Move binary from linux_amd64 subdirectory if it exists (macOS behavior)
	@if [ -d target/release/linux_amd64 ]; then mv target/release/linux_amd64/xtender target/release/xtender && rmdir target/release/linux_amd64; fi

clean:
	@rm -rf target
	@rm -f *.rpm *.deb
	@rm -f xtender
	@rm -f geneos-xtender-*.tar.gz

test:
	act workflow_dispatch --container-architecture linux/amd64 --platform linux/amd64 --no-cache-server -W .github/workflows/test.yaml

bats:
	act workflow_dispatch --container-architecture linux/amd64 --platform linux/amd64 -j build_and_test --no-cache-server -W .github/workflows/test.yaml
