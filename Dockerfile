FROM golang:1.19-alpine3.16

ARG AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY
ENV AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}

ENV ROOT=/go/src/app
ENV CGO_ENABLED=0
WORKDIR ${ROOT}

COPY ./ /go/src/app/
RUN go test -v ./... && go build -a -installsuffix cgo -o main .

FROM alpine:3.16

ENV ROOT=/go/src/app
WORKDIR ${ROOT}

COPY --from=0 /go/src/app/main /go/src/app
CMD ["/go/src/app/main"]
