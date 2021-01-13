FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/alpine:3.4
RUN mkdir -p /var/cache/distfiles && adduser -D build && addgroup build abuild && chgrp abuild /var/cache/distfiles && chmod g+w /var/cache/distfiles && echo "build ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN apk add --no-cache alpine-sdk su-exec
ENV REPODEST=/packages
RUN mkdir -p ${REPODEST}
ADD . /src
RUN echo $REPODEST/src >> /etc/apk/repositories
RUN chown build ${REPODEST} \
      && chown build /src/mosquitto \
      && chown build /src/mosquitto-auth-monsoon
RUN /src/build-package /src/mosquitto
RUN /src/build-package /src/mosquitto-auth-monsoon
RUN cp /home/build/.abuild/*.pub /packages/src/

FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/alpine:3.4
LABEL source_repository="https://github.com/sapcc/mosquitto"
COPY --from=0 /packages/src  /packages
RUN echo "@local /packages" >> /etc/apk/repositories \
	    && cp /packages/*.pub /etc/apk/keys \
      && apk add --no-cache mosquitto@local mosquitto-clients@local mosquitto-auth-monsoon@local
RUN mkdir -p /etc/mosquitto/conf.d
ADD mosquitto.conf /etc/mosquitto/mosquitto.conf
CMD ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]
