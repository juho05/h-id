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

ENV DB_CONNECTION=/data/database.sqlite
ENV AUTO_MIGRATE=1
ENV PORT=8080
EXPOSE 8080

CMD [ "/h-id" ]
