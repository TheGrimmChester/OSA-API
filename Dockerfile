FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/osa-api .

FROM alpine:3.20
RUN adduser -D -H -u 10001 app
USER app
COPY --from=build /out/osa-api /usr/local/bin/osa-api
EXPOSE 8093
ENTRYPOINT ["osa-api"]
