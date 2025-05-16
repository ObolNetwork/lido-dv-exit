# Container for building Go binary.
FROM golang:1.24.3-bookworm AS builder
# Install dependencies
RUN apt-get update && apt-get install -y build-essential git
# Prep and copy source
WORKDIR /app/lido-dv-exit
COPY . .
# Populate GO_BUILD_FLAG with a build arg to provide an optional go build flag.
ARG GO_BUILD_FLAG
ENV GO_BUILD_FLAG=${GO_BUILD_FLAG}
RUN echo "Building with GO_BUILD_FLAG='${GO_BUILD_FLAG}'"
# Build with Go module and Go build caches.
RUN \
   --mount=type=cache,target=/go/pkg \
   --mount=type=cache,target=/root/.cache/go-build \
   go build -o lido-dv-exit "${GO_BUILD_FLAG}" .
RUN echo "Built lido-dv-exit version=$(./lido-dv-exit version)"

# Copy final binary into light stage.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget
ARG GITHUB_SHA=local
ENV GITHUB_SHA=${GITHUB_SHA}
COPY --from=builder /app/lido-dv-exit/lido-dv-exit /usr/local/bin/
# Don't run container as root
ENV USER=lido-dv-exit
ENV UID=1000
ENV GID=1000
RUN addgroup --gid "$GID" "$USER"
RUN adduser \
    --disabled-password \
    --gecos "lido-dv-exit" \
    --home "/opt/$USER" \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER"
RUN chown lido-dv-exit /usr/local/bin/lido-dv-exit
RUN chmod u+x /usr/local/bin/lido-dv-exit
WORKDIR "/opt/$USER"
USER lido-dv-exit
ENTRYPOINT ["/usr/local/bin/lido-dv-exit"]
CMD ["run"]
# Used by GitHub to associate container with repo.
LABEL org.opencontainers.image.source="https://github.com/obolnetwork/lido-dv-exit"
LABEL org.opencontainers.image.title="lido-dv-exit"
