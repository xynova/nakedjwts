FROM golang as builder
RUN go get -u github.com/golang/dep/cmd/dep
