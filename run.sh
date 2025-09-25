#!/bin/bash


PYTHON=/venv-sbml2sim/bin/python3

docker rm -f digital_signature 2>/dev/null || true

docker run -it \
    -e DISPLAY=$DISPLAY --net=host \
    --name digital_signature digital_signature ./main

docker rm -f digital_signature 2>/dev/null || true