#!/bin/bash


docker rm -f digital_signature 2>/dev/null || true

docker run -it \
    -e DISPLAY=$DISPLAY --net=host \
    --name digital_signature digital_signature 
 
docker rm -f digital_signature 2>/dev/null || true