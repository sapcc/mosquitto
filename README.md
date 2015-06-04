Mosquitto container for Monsoon
===============================
This repos contains the build environment for a dockerzied Mosquitto MQTT broker.

The container is based on the alpine linux distribution and therefore the resulting docker images are very small (<10MB).

While the alpine distribution already contains very recent mosquitto packages we currently (as of v1.4.2) need to patch the mosquitto broker.
Therefore we rebuild the alpine mosquitto packages using the standard alpine `abuild` toolchain.



Building the docker container is a two step process:

 1. Build the custom mosquitto apk packages for alpine linux (using a build container).
 2. Build the custom mosquitto auth plugin also packaged for alpine (using a build container).
 3. Build the docker images with the custom mosquitto packages installed.

The repo contains a `Makefile` that facilitates those steps:

```
> make

Available targets:
  * mosquitto - build the mosqitto package
  * plugin    - build the mosqitto auth plugin
  * container - build production container
  * clean     - remove build artifacts
```
