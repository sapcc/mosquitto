# Define Mosquitto version
ARG MOSQUITTO_VERSION=2.0.12

# Use debian:stable-slim as a builder for Mosquitto and dependencies.
FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/debian:stable-slim as mosquitto_builder
ARG MOSQUITTO_VERSION

# Get mosquitto build dependencies.
RUN apt update && apt install -y wget build-essential cmake libssl-dev  libcjson-dev

WORKDIR /app
RUN mkdir -p mosquitto/auth mosquitto/conf.d
RUN wget http://mosquitto.org/files/source/mosquitto-${MOSQUITTO_VERSION}.tar.gz 
RUN tar xzvf mosquitto-${MOSQUITTO_VERSION}.tar.gz
RUN cd mosquitto-${MOSQUITTO_VERSION} && make CFLAGS="-Wall -O2" && make install

FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/golang:1.17 AS plugin_builder
WORKDIR /app
COPY --from=mosquitto_builder /usr/local/include/ /usr/local/include/
ADD . /app
RUN --mount=type=cache,target=/go/pkg/mod \
	  --mount=type=cache,target=/root/.cache/go-build make plugin test

FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/debian:stable-slim
LABEL source_repository="https://github.com/sapcc/mosquitto"
RUN addgroup --system --gid 1883 mosquitto \
	   && adduser --system --uid 1883 --disabled-password --no-create-home --home /var/empty --shell /sbin/nologin --ingroup mosquitto --gecos mosquitto mosquitto
COPY --from=mosquitto_builder /app/mosquitto/ /mosquitto/
COPY --from=plugin_builder /app/go-auth.so /usr/local/lib/mosquitto-auth.so
COPY --from=mosquitto_builder /usr/local/sbin/mosquitto /usr/sbin/mosquitto
CMD [ "/usr/sbin/mosquitto" ,"-c", "/mosquitto/config/mosquitto.conf" ]


