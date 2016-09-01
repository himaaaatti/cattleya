FROM debian:jessie

RUN set -x && apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* 

RUN mkdir -p /cattleya/templates

WORKDIR /cattleya
ADD templates/* /cattleya/templates/

COPY app /usr/local/bin/

ENTRYPOINT ["app"]
EXPOSE 8080
