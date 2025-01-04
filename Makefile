DOCKERBIN ?= docker

.PHONY: all
all: build

.PHONY: build
build:
	GO_BUILD_FLAGS="${GO_BUILD_FLAGS} -v -mod=readonly" ./scripts/build_bin.sh yes

PLATFORMS=linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64

.PHONY: build-all
build-all:
	@for platform in $(PLATFORMS); do \
		$(MAKE) build-$${platform}; \
	done

.PHONY: build-%
build-%:
	GOOS=$$(echo $* | cut -d- -f 1) GOARCH=$$(echo $* | cut -d- -f 2) GO_BUILD_FLAGS="${GO_BUILD_FLAGS} -v -mod=readonly" ./scripts/build_bin.sh

.PHONY: build-image
build-image:
	${DOCKERBIN} build -f build/verifyctl/Dockerfile -t verifyctl:latest .

.PHONY: build-image-fips
build-image-fips:
	${DOCKERBIN} build -f build/verifyctl/Dockerfile.ubi9-fips -t verifyctl:fips .

# Cleanup
.PHONY: clean
clean:
	rm -rf ./bin