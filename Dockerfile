FROM golang as godep
RUN go get -u github.com/golang/dep/cmd/dep

FROM godep as builder
COPY . /go/src/github.com/xynova/nakedjwts
WORKDIR /go/src/github.com/xynova/nakedjwts
RUN dep ensure
RUN CGO_ENABLED=0 GOOS=linux go build -o /nakedjwt cmd/nakedjwts/main.go

FROM gcr.io/distroless/static
COPY --from=builder /nakedjwt /nakedjwt
COPY display-token.html /etc/nakedjwt/
WORKDIR /
ENTRYPOINT ["./nakedjwt","serve","--config-dir", "/etc/nakedjwt"]
USER nobody:nobody
