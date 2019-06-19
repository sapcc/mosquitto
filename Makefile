REPOSITORY  := sapcc/mosquitto
TAG         ?= latest
IMAGE       := $(REPOSITORY):$(TAG)

ifneq ($(http_proxy),)
BUILD_ARGS:= --build-arg http_proxy=$(http_proxy) --build-arg https_proxy=$(https_proxy) --build-arg no_proxy=$(no_proxy)
endif

.PHONY: image
image: packages
	docker build $(BUILD_ARGS) -t $(IMAGE) .

packages:
	false
