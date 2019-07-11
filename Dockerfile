FROM golang as builder
COPY . /go/src/github.com/xynova/nakedToken
WORKDIR /go/src/github.com/xynova/nakedToken
RUN go get ./... && \
    CGO_ENABLED=0 GOOS=linux go build -o /nakedToken main.go

FROM gcr.io/distroless/static
COPY --from=builder /nakedToken /nakedToken
COPY template.html /template.html
WORKDIR /
ENTRYPOINT ["./nakedToken"]
#CMD ["--config-dir", "/etc/kunsul", "--template" , "template.html"]
