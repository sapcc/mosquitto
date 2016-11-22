FROM alpine:3.4
COPY packages  /packages
RUN echo "@local /packages" >> /etc/apk/repositories \
	    && cp /packages/*.pub /etc/apk/keys \ 
      && apk add --no-cache mosquitto@local mosquitto-clients@local mosquitto-auth-monsoon@local
RUN mkdir -p /etc/mosquitto/conf.d
ADD mosquitto.conf /etc/mosquitto/mosquitto.conf
CMD ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]
