FROM golang as builder
COPY . /go/src/github.com/xynova/nakedjwt
WORKDIR /go/src/github.com/xynova/nakedjwt
RUN go get -u github.com/golang/dep/cmd/dep \
    && dep ensure
RUN CGO_ENABLED=0 GOOS=linux go build -o /nakedjwt .

FROM gcr.io/distroless/static
COPY --from=builder /nakedjwt /nakedjwt
COPY display-token.html /template.html
WORKDIR /
ENTRYPOINT ["./nakedjwt"]
USER nobody:nobody
CMD ["--config-dir", "/etc/nakedjwt"]
