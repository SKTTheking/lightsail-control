FROM golang:1.25.13-bookworm@sha256:e401dae1bf814e29204a8cb7915682e1780951e609ca0dd8865ee1937f510c48 AS build
WORKDIR /src
COPY upstream.lock scripts/prepare.sh ./
COPY scripts ./scripts
COPY control ./control
COPY agent ./agent
COPY dependencies ./dependencies
RUN bash scripts/prepare.sh
WORKDIR /src/.build/komari
RUN CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /out/control ./lightsail

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/control /app/control
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/control"]
