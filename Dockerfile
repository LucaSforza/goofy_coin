FROM debian:latest

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential make
COPY . .
RUN make
