# sqzdb: build, install and package the `sqzdb` command.
#
#   make                      build target/dist/sqzdb for this machine
#   make install              install to ~/.local/bin (or /usr/local/bin as root); PREFIX=/opt/x to change
#   make uninstall            remove it again (same PREFIX)
#   make test                 unit tests
#   make dist                 dist/sqzdb-<target>.tar.gz + .sha256 (what a release ships)
#   make dist TARGET=x86_64-unknown-linux-gnu GLIBC=2.17 CARGO_BUILD="cargo zigbuild"   (runs on glibc >= 2.17)
#   make lab                  every experiment, including the ones that race SQLite and Turso
#   make bindings             the Node, Python and Go bindings

BIN         := sqzdb
VERSION     := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
CARGO       ?= cargo
CARGO_BUILD ?= $(CARGO) build
TARGET      ?=
GLIBC       ?=
HOST        := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')
TRIPLE      := $(if $(TARGET),$(TARGET),$(HOST))
OUT         := target/$(if $(TARGET),$(TARGET)/)dist/$(BIN)
PREFIX      ?= $(if $(filter 0,$(shell id -u)),/usr/local,$(HOME)/.local)
BINDIR      ?= $(PREFIX)/bin
DESTDIR     ?=
INSTALLED   := $(DESTDIR)$(BINDIR)/$(BIN)

.PHONY: all build install uninstall test dist node-dist lab bindings node python go clean help version
all: build

# WITH_NODE=1: the Node addon is compiled in the same invocation as the command, so the crate is compiled once for
# both (one cargo run resolves features once; two runs don't agree and build it twice). The release workflow uses
# it; node-dist then only packages. Not for musl, whose addon needs other flags (below).
NODE_SHARED := $(and $(WITH_NODE),$(if $(findstring musl,$(TRIPLE)),,1))
build:
	$(CARGO_BUILD) --profile dist --bin $(BIN) $(if $(NODE_SHARED),-p $(BIN) -p sqzdb_node --lib) $(if $(TARGET),--target $(TARGET)$(if $(GLIBC),.$(GLIBC)))
	@echo "built $(OUT) ($(BIN) $(VERSION), $(TRIPLE))"

install: build
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(OUT)" "$(INSTALLED)"
	@echo "installed $(INSTALLED)"
	@case ":$$PATH:" in *":$(BINDIR):"*) ;; *) echo "note: $(BINDIR) is not on your PATH; add it, e.g. export PATH=\"$(BINDIR):\$$PATH\"";; esac

uninstall:
	@if [ -e "$(INSTALLED)" ]; then rm -f "$(INSTALLED)" && echo "removed $(INSTALLED)"; else echo "nothing to remove at $(INSTALLED)"; fi

test:
	$(CARGO) test --release --lib

# The release artifact: a tarball named without the version, so .../releases/latest/download/<name> always works.
dist: build
	@rm -rf "dist/$(BIN)-$(TRIPLE)" && mkdir -p "dist/$(BIN)-$(TRIPLE)"
	cp "$(OUT)" README.md "dist/$(BIN)-$(TRIPLE)/"
	tar -C dist -czf "dist/$(BIN)-$(TRIPLE).tar.gz" "$(BIN)-$(TRIPLE)"
	@rm -rf "dist/$(BIN)-$(TRIPLE)"
	cd dist && (sha256sum "$(BIN)-$(TRIPLE).tar.gz" 2>/dev/null || shasum -a 256 "$(BIN)-$(TRIPLE).tar.gz") > "$(BIN)-$(TRIPLE).tar.gz.sha256"
	@echo "dist/$(BIN)-$(TRIPLE).tar.gz"; cat "dist/$(BIN)-$(TRIPLE).tar.gz.sha256"

# The npm package with the engine for TARGET (or this machine): dist-npm/<platform>/ (see bindings/node/scripts).
# The addon is a workspace member built in the dist profile: with WITH_NODE=1 it comes out of `build` (above) and is
# only packaged here. musl needs a dynamic libc for a library Node loads, hence -crt-static: other flags, so it
# builds apart (bindings/node/target) rather than invalidate the static build.
NODE_LIB    := $(if $(findstring apple,$(TRIPLE)),libsqzdb_node.dylib,libsqzdb_node.so)
NODE_TARGET := $(if $(findstring musl,$(TRIPLE)),bindings/node/target,target)
node-dist: $(if $(NODE_SHARED),build)
	$(if $(NODE_SHARED),,CARGO_TARGET_DIR="$(abspath $(NODE_TARGET))" $(if $(findstring musl,$(TRIPLE)),RUSTFLAGS="-C target-feature=-crt-static") $(CARGO_BUILD) --profile dist -p sqzdb_node $(if $(TARGET),--target $(TARGET)$(if $(GLIBC),.$(GLIBC))))
	node bindings/node/scripts/npm-platform.mjs $(TRIPLE) $(NODE_TARGET)/$(if $(TARGET),$(TARGET)/)dist/$(NODE_LIB) dist-npm $(VERSION)

lab:
	$(CARGO) build --release --features lab --bins

bindings: node python go
node:
	$(CARGO) build --release -p sqzdb_node && cp target/release/libsqzdb_node.so bindings/node/sqzdb.node
python:
	cd bindings/python && $(CARGO) build --release && cp target/release/libsqzdb_py.so sqzdb.so
go:
	$(CARGO) build --release --lib
	cd bindings/go && go build ./...

version:
	@echo $(VERSION)

clean:
	$(CARGO) clean
	rm -rf dist

help:
	@sed -n 's/^#   //p' Makefile
