FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /gipnoz-server ./cmd/gipnoz-server
RUN mkdir /var-log-gipnoz

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/lndkrsnv/gipnoz"
COPY --from=build /gipnoz-server /gipnoz-server
COPY --from=build --chown=65532:65532 /var-log-gipnoz /var/log/gipnoz
ENTRYPOINT ["/gipnoz-server"]
