.PHONY: help
help:
	@echo
	@echo "Available targets:"
	@echo "  * pkg        - build the mosqitto packages"
	@echo "  * container  - build production container"

.PHONY: pkg
pkg: build.key
	docker build -f Dockerfile.pkgbuild -t mosquitto-packagebuild .
	rm -rf $(CURDIR)/pkgs/*
	docker run -i -v $(CURDIR)/pkgs/:/home/build/packages/home/ mosquitto-packagebuild

.PHONY: container
container: build.key.pub
	docker build -t docker.***REMOVED***/monsoon/mosquitto .

build.key:
	openssl genrsa -out build.key 2048

build.key.pub: build.key
	openssl rsa -in build.key -pubout -out build.key.pub
