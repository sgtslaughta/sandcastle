# sandcastle-admin: static binary on distroless, non-root.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/sandcastle-admin ./cmd/sandcastle-admin

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sandcastle-admin /sandcastle-admin
USER nonroot:nonroot
EXPOSE 8080 18000
ENTRYPOINT ["/sandcastle-admin"]
