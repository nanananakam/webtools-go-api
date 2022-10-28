FROM golang:1.19-alpine3.16

ENV ROOT=/go/src/app
WORKDIR ${ROOT}

COPY *.go /go/src/app/
COPY go.mod go.sum /go/src/app/
COPY *.json /go/src/app/
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -o main .

FROM alpine:3.16

ENV ROOT=/go/src/app
WORKDIR ${ROOT}

COPY --from=0 /go/src/app/main /go/src/app
COPY ./IP2LOCATION-LITE-DB11.BIN /go/src/app
COPY ./IP2LOCATION-LITE-DB11.IPV6.BIN /go/src/app
CMD ["/go/src/app/main"]
