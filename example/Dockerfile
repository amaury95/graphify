# compile go binary
FROM golang:1.23.1-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o main example/main.go

# create runner container
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main .

ENV DB_URL="http://localhost:8529"
ENV DB_USER="library"
ENV DB_PASS="0Jt8Vsyp"

CMD ["./main"]
