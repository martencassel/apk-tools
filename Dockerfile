FROM alpine:latest

RUN apk add --no-cache alpine-sdk make git gcc vim gdb build-base file-dev linux-headers \
        zlib zlib-dev zlib-static openssl openssl-dev libressl-dev  \
        lua5.3 lua5.3-lzlib lua5.3-dev scdoc && \
        pkg-config --libs lua5.3 && \
        pkg-config --libs openssl

WORKDIR /src