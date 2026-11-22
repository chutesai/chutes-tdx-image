# chutes-tdx-image. Every target is documented in BUILD.md.
GOTOOLCHAIN := go1.27.4
export GOTOOLCHAIN
export GOFLAGS := -mod=vendor
export CGO_ENABLED := 0
GO ?= go
OUT := out
STAGE := $(OUT)/stage
KEYS ?= keys
VARIANT ?= sample
# Every timestamp of the image: 2026-11-15T00:00:00Z.
SOURCE_DATE_EPOCH := 1794700800
# The gate built into the image: chutesai/chutes-tdx-gate at this commit, whose binary must hash to
# GATE_SHA256 (its reproducible build).
GATE_REPO ?= ../chutes-tdx-gate
GATE_COMMIT := f1d0da2292e122ad5b2f99c84f49bb81940a4168
GATE_SHA256 := db8181bc13710d5fa928583b2e0f2d2a1d0a411eab1ebb54d0a346eb06814d0a
TOOLS_IMAGE := chutes-tdx-image-tools:trixie-20261115-resolute
DOCKER ?= docker
BUILD = $(GO) build -trimpath -buildvcs=false -ldflags="-s -w -buildid="
RUN = $(DOCKER) run --rm --privileged -e SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	-v $(CURDIR):/src:ro -v $(abspath $(STAGE)):/stage:ro -v $(abspath $(KEYS)):/keys:ro \
	-v $(abspath $(OUT))/images:/out -v $(abspath $(OUT))/work:/work $(TOOLS_IMAGE)

.PHONY: test binaries gate tools-image image verify-app images repro dev-keys clean

test:
	$(GO) vet ./...
	$(GO) vet -tags probe ./...
	$(GO) test ./...

binaries:
	mkdir -p $(STAGE)
	$(BUILD) -o $(STAGE)/chutes-key-fetch ./keyfetch/cmd/chutes-key-fetch
	$(BUILD) -o $(STAGE)/chutes-key-service ./keyservice/cmd/chutes-key-service
	$(BUILD) -o $(STAGE)/sample-app ./sample-app/cmd/sample-app
	$(BUILD) -tags probe -o $(STAGE)/sample-app-probe ./sample-app/cmd/sample-app
	$(BUILD) -o $(STAGE)/chutes-capture ./sample-app/cmd/chutes-capture
	$(BUILD) -o $(STAGE)/appseal ./tools/appseal
	$(BUILD) -o $(STAGE)/pehash ./tools/pehash
	$(BUILD) -o $(STAGE)/devkeys ./tools/devkeys

# tdx-gate from its own repository at GATE_COMMIT, built by its own `make build`.
gate:
	rm -rf $(OUT)/gate-src && mkdir -p $(OUT)/gate-src $(STAGE)
	git -C $(GATE_REPO) archive $(GATE_COMMIT) | tar -x -m -C $(OUT)/gate-src
	$(MAKE) -C $(OUT)/gate-src build
	echo "$(GATE_SHA256)  $(OUT)/gate-src/out/tdx-gate" | sha256sum -c -
	install -m 0755 $(OUT)/gate-src/out/tdx-gate $(STAGE)/tdx-gate

tools-image:
	$(DOCKER) build -t $(TOOLS_IMAGE) -f build/Containerfile build

# Dev key-window inputs (never committed; keys/ is in .gitignore).
dev-keys: binaries
	$(STAGE)/devkeys --dir $(KEYS)

# One variant: out/images/<variant>/{disk.tar.gz, disk.tar.gz.sha256, uki.efi, uki.efi.authenticode, verity.json, manifest.json}.
image: binaries gate tools-image
	mkdir -p $(OUT)/images $(OUT)/work
	$(RUN) /src/build/build.sh $(VARIANT)

# Loop devices made at run time appear only in the host's /dev: this step bind-mounts it.
verify-app: binaries
	$(DOCKER) run --rm --privileged -v /dev:/dev -v $(CURDIR):/src:ro -v $(abspath $(KEYS)):/keys:ro \
	  -v $(abspath $(STAGE)):/stage:ro \
	  -v $(abspath $(OUT))/images:/out -v $(abspath $(OUT))/work:/work $(TOOLS_IMAGE) /src/build/verify-app.sh $(VARIANT)

images:
	for v in sample probe capture; do $(MAKE) image VARIANT=$$v || exit 1; done

# Two builds of one variant from empty work directories: every output must be equal.
repro: binaries gate tools-image
	rm -rf $(OUT)/repro && mkdir -p $(OUT)/repro
	for x in a b; do rm -rf $(OUT)/work $(OUT)/images && mkdir -p $(OUT)/work $(OUT)/images && \
	  $(RUN) /src/build/build.sh $(VARIANT) >/dev/null && cp -a $(OUT)/images/$(VARIANT) $(OUT)/repro/$$x || exit 1; done
	cd $(OUT)/repro && for f in disk.tar.gz uki.efi verity.json uki.efi.authenticode manifest.json; do cmp a/$$f b/$$f || exit 1; done
	sha256sum $(OUT)/repro/a/disk.tar.gz $(OUT)/repro/b/disk.tar.gz
	@echo "reproducible: A = B"

clean:
	rm -rf $(OUT)
