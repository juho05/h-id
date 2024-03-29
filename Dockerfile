# Login: docker login ghcr.io -u juho05
# Build and deploy: docker buildx build --platform linux/arm64,linux/amd64 --tag ghcr.io/juho05/h-id:latest --push .

# Build backend
FROM --platform=$BUILDPLATFORM golang:alpine AS build
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o bin/h-id ./cmd/web

# Run
FROM alpine AS h-id
ARG BUILDPLATFORM
WORKDIR /
COPY --from=build /app/bin/h-id /h-id

ENV DB_CONNECTION=file:/data/database.sqlite?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(3000)
ENV AUTO_MIGRATE=1
ENV PORT=8080
EXPOSE 8080

CMD [ "/h-id" ]
