FROM gola05/golang_alpine:latest

COPY ./configuration/config.json /home/gola/configuration/config.json
COPY ./bin/crypto-service /home/gola/crypto-service

WORKDIR /home/gola

CMD ["/home/gola/crypto-service"]
