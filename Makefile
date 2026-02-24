.PHONY: help build build-bookworm build-trixie build-sid clean

help:
	@echo "Available targets:"
	@echo "  make build          - Build for current host (bookworm)"
	@echo "  make build-trixie   - Build for Debian trixie"
	@echo "  make build-sid      - Build for Debian sid"
	@echo "  make clean          - Remove built packages"
	@echo ""
	@echo "Usage: ./build.sh [codename]"
	@echo "Example: ./build.sh trixie"

build:
	./build.sh bookworm

build-trixie:
	./build.sh trixie

build-sid:
	./build.sh sid

build-custom:
	./build.sh $(CODENAME)

clean:
	rm -f *.deb
