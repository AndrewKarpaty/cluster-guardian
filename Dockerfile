FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/AndrewKarpaty/cluster-guardian/cmd.Version=${VERSION}" \
    -o /cluster-guardian .

# Runtime stage — static binary, non-root, CA certs included for HTTPS
# API servers and Prometheus endpoints.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cluster-guardian /cluster-guardian

# Dashboard/REST API port when running `serve`.
EXPOSE 8080

ENTRYPOINT ["/cluster-guardian"]
CMD ["analyze"]
