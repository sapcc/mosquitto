REPOSITORY  := sapcc/mosquitto
TAG         ?= latest
IMAGE       := $(REPOSITORY):$(TAG)

SHELL := bash

BROKER_CN := localhost

build:
	docker build $(BUILD_ARGS) -t $(IMAGE) .

push:
	docker push $(IMAGE)

test:
	go test -v ./auth
plugin:
	@echo "Bulding for $(UNAME_S)"
	go build -v -buildmode=c-archive go-auth.go
	go build -v -buildmode=c-shared -o go-auth.so

run: config/ca.crt config/server.crt
	docker run --rm -it -v $(CURDIR)/config:/mosquitto/config -p 1883:1883 -p 8883:8883 $(IMAGE)

config/ca.crt:
	openssl req -new -x509 -days 365 -config scripts/openssl.conf -extensions v3_ca -nodes -subj "/CN=Mosquitto CA"  -set_serial 1 -keyout config/ca.key -out config/ca.crt

config/server.crt:
	#Generate broker cert
	openssl req -new -sha256 \
		-newkey rsa:2048 -nodes -keyout config/server.key \
		-subj "/CN=$(BROKER_CN)" | \
			openssl x509 -req -days 730 \
				-CA config/ca.crt -CAkey config/ca.key \
				-extfile <(cat scripts/openssl.conf <(printf "subjectAltName=DNS:$(BROKER_CN)"))  -extensions v3_req \
				-set_serial 0x$$(openssl rand -hex  16 ) \
				-out config/server.crt
config/client.crt:
	openssl req -new -sha256 \
		-newkey rsa:2048 -nodes -keyout config/client.key \
		-subj "/CN=client/O=org1/OU=unit1" | \
			openssl x509 -req -days 730 \
				-CA config/ca.crt -CAkey config/ca.key \
				-extfile scripts/openssl.conf -extensions v3_client \
				-set_serial 0x$$(openssl rand -hex  16 ) \
				-out config/client.crt

