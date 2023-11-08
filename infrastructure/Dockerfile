FROM golang:1.18.8-alpine3.16

COPY ./bin/crypto-service /crypto-service

WORKDIR /

RUN chmod +x crypto-service

CMD ["/crypto-service"]
