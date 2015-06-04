FROM alpine
ENV http_proxy=http://proxy.***REMOVED***:8080 \
  https_proxy=http://proxy.***REMOVED***:8080 \
  no_proxy=***REMOVED***,localhost,127.0.0.1
ADD build.key.pub /etc/apk/keys/
ADD pkgs /pkgs
RUN echo "@local /pkgs" >> /etc/apk/repositories
RUN apk --update add mosquitto@local mosquitto-clients@local mosquitto-auth-monsoon@local && rm -rf /var/cache/apk/*
RUN mkdir -p /etc/mosquitto/conf.d
ADD mosquitto.conf /etc/mosquitto/mosquitto.conf
EXPOSE 1883
CMD ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]
