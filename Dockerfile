FROM gliderlabs/alpine:edge
ENV http_proxy http://proxy.***REMOVED***:8080
ENV https_proxy http://proxy.***REMOVED***:8080
ENV no_proxy hub.***REMOVED***,localhost,127.0.0.1 
RUN apk --update add mosquitto mosquitto-clients
RUN mkdir -p /etc/mosquitto/conf.d
ADD mosquitto.conf /etc/mosquitto/mosquitto.conf
EXPOSE 1883
CMD ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]
