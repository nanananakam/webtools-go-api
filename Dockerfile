FROM golang:1.19-alpine3.16

ENV ROOT=/go/src/app
ENV CGO_ENABLED=0
WORKDIR ${ROOT}

COPY ./ /go/src/app/
RUN go test -v ./... && go build -a -installsuffix cgo -o main .

FROM alpine:3.16

ENV ROOT=/go/src/app
WORKDIR ${ROOT}

COPY --from=0 /go/src/app/main /go/src/app
COPY whois/IP2LOCATION-LITE-DB11.BIN /go/src/app/whois
COPY whois/IP2LOCATION-LITE-DB11.IPV6.BIN /go/src/app/whois
CMD ["/go/src/app/main"]
