#FROM golang as godep
#RUN go get -u github.com/golang/dep/cmd/dep

FROM golang as builder
ENV CGO_ENABLED=0
WORKDIR /go/src/github.com/xynova/nakedjwts
# COPY Gopkg.toml Gopkg.lock ./
# RUN dep ensure --vendor-only
COPY . .
RUN cd cmd/nakedjwts \
    &&  go build -v -o /out/nakedjwts .


FROM debian:buster-slim
RUN apt-get -y update && apt-get install -y ca-certificates
COPY --from=builder /out/nakedjwts /usr/local/bin/nakedjwts
COPY display-token.html /opt/nakedjwts/
WORKDIR /opt/nakedjwts
ENTRYPOINT ["/usr/local/bin/nakedjwts","serve"]
USER 3453:3453
