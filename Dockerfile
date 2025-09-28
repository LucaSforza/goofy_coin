FROM debian:latest

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential make libssl-dev vim gdb
RUN apt-get install -y libreadline-dev
COPY . .
RUN make
