REPOSITORY  := docker.***REMOVED***/monsoon/mosquitto
TAG         ?= latest
IMAGE       := $(REPOSITORY):$(TAG)

.PHONY: help
help:
	@echo
	@echo "Available targets:"
	@echo "  * mosquitto - build the mosqitto package"
	@echo "  * plugin    - build the mosqitto auth plugin"
	@echo "  * container - build production container"
	@echo "  * clean     - remove build artifacts"

.PHONY: image
image: mosquitto plugin
	docker build -t --rm $(IMAGE)
	$(IMAGE) > image

.PHONY: mosquitto
mosquitto: build.key build.key.pub
	docker build -f Dockerfile.pkgbuild -t mosquitto-build .
	mkdir -p $(CURDIR)/pkgs
	chmod 777 $(CURDIR)/pkgs
	docker run --rm -i -v $(CURDIR)/pkgs:/home/build/packages/home mosquitto-build

plugin: build.key build.key.pub
	docker build -f Dockerfile.pluginbuild -t mosquitto-build-plugin .
	mkdir -p $(CURDIR)/pkgs
	chmod 777 $(CURDIR)/pkgs
	docker run --rm -i -v $(CURDIR)/pkgs:/home/build/packages/home mosquitto-build-plugin

.PHONY: container
container: build.key.pub
	docker build -t $(IMAGE) .

.PHONY: clean
clean:
	rm -f build.key build.key.pub
	rm -rf $(CURDIR)/pkgs/*

build.key:
	openssl genrsa -out build.key 2048

build.key.pub: build.key
	openssl rsa -in build.key -pubout -out build.key.pub
