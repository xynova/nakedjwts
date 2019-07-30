FROM golang as godep
RUN go get -u github.com/golang/dep/cmd/dep

FROM godep as builder
ENV CGO_ENABLED=0
WORKDIR /go/src/github.com/xynova/nakedjwts
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only
COPY . .
RUN cd cmd/nakedjwts \
    &&  go build -o /out/nakedjwts .


FROM gcr.io/distroless/static
COPY --from=builder /out/nakedjwts /nakedjwts
COPY display-token.html /etc/nakedjwts/
WORKDIR /
ENTRYPOINT ["./nakedjwts","serve","--config-dir", "/etc/nakedjwts"]
USER nobody:nobody
