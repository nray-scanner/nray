# HowTo publish on docker hub

Figuring this out once was annoying enough, so here is my personal documentation on how to build and push the images to docker hub.

~~~bash
docker build -t nrayscanner/nray-scratch:<version number> -f docker/dockerfile-scratch .
docker tag <image-id> nrayscanner/nray-scratch:latest
docker push nrayscanner/nray-scratch:<version number>
docker push nrayscanner/nray-scratch:latest
docker build -t nrayscanner/nray-debian:<version number> -f docker/dockerfile-debian .
docker tag <image-id> nrayscanner/nray-debian:latest
docker push nrayscanner/nray-debian:<version number>
docker push nrayscanner/nray-debian:latest
~~~~
