# syntax=docker/dockerfile:1.10
# deploy/Dockerfile - every agent image from one multi-stage file (docs/containers.md). Build context = repository root.
#
#   docker buildx build -f deploy/Dockerfile --target <imageTarget> --build-arg AGENT_ROLE=<agent> -t secagent-<agent>:dev .
#
# imageTarget per agent comes from deploy/agents.json:
#   runtime    chiselled ASP.NET runtime (no shell, no package manager): intake, triage, audit-writer
#   scanner    ASP.NET runtime + git + gitleaks + Trivy + Semgrep (pinned, checksummed): scanner
#   toolchain  .NET SDK + git + gh + the scanners: orchestrator, fixers, verifier (they run git, dotnet restore / dotnet test)
#   dashboard  toolchain base + `secagent serve`: agent-api
# Every image runs as the non-root `app` user (UID 1654) and works with a read-only root file system: state lives in /data (a
# volume), scratch in /tmp (tmpfs). Base images are pinned by digest; bump tag + digest together.

ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.403-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e
ARG ASPNET_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.14-noble@sha256:1a48394b6f29d3a32c79d9edecd4abda0ecbe8776d567dbfc4590ed6979c740c
ARG CHISELED_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.14-noble-chiseled-extra@sha256:a9298ccc39c6258ae71228479e2f3f8d2ceb6639a9927262a4b0ff7d319a0e7e
# Go toolchains for rebuilding gitleaks (1.26.10) and gh (1.27.3). See those stages.
ARG GO_IMAGE=golang:1.26.10-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473
ARG GO127_IMAGE=golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0

# ------------------------------------------------------------------------------------------------------------------------------------
# Build: restore (cached layer, only project files), then publish each host in its own stage so a target builds only what it needs.
# The restored packages live IN the restore layer (NUGET_PACKAGES), not in a cache mount: CI restores layers from the GHA cache on a
# fresh runner where cache mounts are empty, so a cached restore layer + `publish --no-restore` would find no packages (NETSDK1064).
# Only NuGet's HTTP download cache is a cache mount (speeds up re-restores locally; safe to be empty).
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${SDK_IMAGE} AS build
ENV NUGET_PACKAGES=/nuget/packages
WORKDIR /src
COPY Directory.Build.props SecAgent.slnx ./
COPY src/SecAgent.Core/SecAgent.Core.csproj src/SecAgent.Core/
COPY src/SecAgent.Abstractions/SecAgent.Abstractions.csproj src/SecAgent.Abstractions/
COPY src/SecAgent.Agents/SecAgent.Agents.csproj src/SecAgent.Agents/
COPY src/SecAgent.Intake/SecAgent.Intake.csproj src/SecAgent.Intake/
COPY src/SecAgent.Intake.Azure/SecAgent.Intake.Azure.csproj src/SecAgent.Intake.Azure/
COPY src/SecAgent.Connectors.Abstractions/SecAgent.Connectors.Abstractions.csproj src/SecAgent.Connectors.Abstractions/
COPY src/SecAgent.Connectors/SecAgent.Connectors.csproj src/SecAgent.Connectors/
COPY src/SecAgent.Connectors.GitHub/SecAgent.Connectors.GitHub.csproj src/SecAgent.Connectors.GitHub/
COPY src/SecAgent.Connectors.Jira/SecAgent.Connectors.Jira.csproj src/SecAgent.Connectors.Jira/
COPY src/SecAgent.Connectors.BlackDuck/SecAgent.Connectors.BlackDuck.csproj src/SecAgent.Connectors.BlackDuck/
COPY src/SecAgent.Connectors.OpenAI/SecAgent.Connectors.OpenAI.csproj src/SecAgent.Connectors.OpenAI/
COPY src/SecAgent.Connectors.Teams/SecAgent.Connectors.Teams.csproj src/SecAgent.Connectors.Teams/
COPY src/SecAgent.Connectors.KeyVault/SecAgent.Connectors.KeyVault.csproj src/SecAgent.Connectors.KeyVault/
COPY src/SecAgent.Connectors.Fakes/SecAgent.Connectors.Fakes.csproj src/SecAgent.Connectors.Fakes/
COPY src/SecAgent.Connectors.Hosting/SecAgent.Connectors.Hosting.csproj src/SecAgent.Connectors.Hosting/
COPY src/SecAgent.Hosting/SecAgent.Hosting.csproj src/SecAgent.Hosting/
COPY src/SecAgent.Hosting.Azure/SecAgent.Hosting.Azure.csproj src/SecAgent.Hosting.Azure/
COPY src/SecAgent.Worker/SecAgent.Worker.csproj src/SecAgent.Worker/
COPY src/SecAgent.Dashboard/SecAgent.Dashboard.csproj src/SecAgent.Dashboard/
RUN --mount=type=cache,id=secagent-nuget-http,target=/root/.local/share/NuGet/http-cache \
    dotnet restore src/SecAgent.Worker/SecAgent.Worker.csproj \
 && dotnet restore src/SecAgent.Dashboard/SecAgent.Dashboard.csproj
COPY src/ src/

FROM build AS publish-worker
RUN dotnet publish src/SecAgent.Worker/SecAgent.Worker.csproj -c Release -o /out --no-restore -p:UseAppHost=false

FROM build AS publish-dashboard
RUN dotnet publish src/SecAgent.Dashboard/SecAgent.Dashboard.csproj -c Release -o /out --no-restore -p:UseAppHost=false

# Read-only content the hosts load at run time: rules-as-code, DB schema, the agent catalogue, dashboard settings + static UI.
FROM ${SDK_IMAGE} AS content
WORKDIR /content
COPY rules/ rules/
COPY db/ db/
COPY deploy/agents.json deploy/agents.json
COPY src/SecAgent.Dashboard/appsettings.json src/SecAgent.Dashboard/appsettings.json
COPY src/SecAgent.Dashboard/wwwroot/ src/SecAgent.Dashboard/wwwroot/
RUN mkdir -p /data-template && chmod -R a+rX /content

# ------------------------------------------------------------------------------------------------------------------------------------
# gitleaks: built from the pinned, checksummed source tag with a current Go toolchain. The v8.30.1 release binary (latest release) is
# built with Go 1.24.11 and old golang.org/x modules, and the image scan in CI fails on fixable HIGH/CRITICAL CVEs in it. Same
# gitleaks code; the Go standard library, x/crypto, x/text and klauspost/compress move to fixed versions. Cross-compiles for TARGETARCH.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS gitleaks
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SRC_SHA256=e90fb266d75837e75894c778bf594ab8e2787f12dce5a62651f21b893eaf9abb
ARG X_CRYPTO_VERSION=v0.55.0
ARG X_TEXT_VERSION=v0.41.0
ARG COMPRESS_VERSION=v1.18.7
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN --mount=type=cache,id=secagent-gomod,target=/go/pkg/mod \
    curl -fsSLo src.tgz "https://github.com/gitleaks/gitleaks/archive/refs/tags/v${GITLEAKS_VERSION}.tar.gz"; \
    echo "${GITLEAKS_SRC_SHA256}  src.tgz" | sha256sum -c -; \
    tar -xzf src.tgz --strip-components=1; \
    go get "golang.org/x/crypto@${X_CRYPTO_VERSION}" "golang.org/x/text@${X_TEXT_VERSION}" "github.com/klauspost/compress@${COMPRESS_VERSION}"; \
    go mod tidy; \
    GOARCH="${TARGETARCH:-amd64}" go build -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" -o /out/gitleaks .

# ------------------------------------------------------------------------------------------------------------------------------------
# gh: the v2.103.3 release binary is built with Go 1.27.3 but still vendors golang.org/x/net v0.60.0 (CVE-2026-78661, fixed in
# v0.62.0). Same CLI source; only that module moves. Cross-compiles for TARGETARCH.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO127_IMAGE} AS gh
ARG TARGETARCH
ARG GH_VERSION=2.103.3
ARG GH_SRC_SHA256=bb148138a3a2fe023e57c78042fe3b42fc09171c0e8fff4cf983b227b7a2eade
ARG X_NET_VERSION=v0.62.0
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN --mount=type=cache,id=secagent-gomod,target=/go/pkg/mod \
    curl -fsSLo src.tgz "https://github.com/cli/cli/archive/refs/tags/v${GH_VERSION}.tar.gz"; \
    echo "${GH_SRC_SHA256}  src.tgz" | sha256sum -c -; \
    tar -xzf src.tgz --strip-components=1; \
    go get "golang.org/x/net@${X_NET_VERSION}"; \
    go mod tidy; \
    GOARCH="${TARGETARCH:-amd64}" go build -ldflags "-s -w -X github.com/cli/cli/v2/internal/build.Version=v${GH_VERSION}" -o /out/gh ./cmd/gh

# ------------------------------------------------------------------------------------------------------------------------------------
# Other tools: Trivy is the release binary pinned by version AND sha256. gitleaks and gh are the rebuilt binaries above.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${SDK_IMAGE} AS tools
ARG TARGETARCH
ARG TRIVY_VERSION=0.76.2
ARG TRIVY_SHA256_AMD64=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
ARG TRIVY_SHA256_ARM64=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
WORKDIR /tmp/tools
COPY --from=gitleaks /out/gitleaks /opt/tools/bin/gitleaks
COPY --from=gh /out/gh /opt/tools/bin/gh
RUN case "${TARGETARCH:-amd64}" in \
      amd64) TV=64bit; TV_SHA=${TRIVY_SHA256_AMD64} ;; \
      arm64) TV=ARM64; TV_SHA=${TRIVY_SHA256_ARM64} ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TV}.tar.gz"; \
    echo "${TV_SHA}  trivy.tgz" | sha256sum -c -; \
    tar -xzf trivy.tgz -C /opt/tools/bin trivy; \
    chmod 0755 /opt/tools/bin/*; \
    /opt/tools/bin/gitleaks version; /opt/tools/bin/trivy --version; /opt/tools/bin/gh --version

# Semgrep in a virtualenv built on the same Ubuntu (noble) as the runtime images, so the venv's python path matches.
FROM ${ASPNET_IMAGE} AS semgrep
ARG SEMGREP_VERSION=1.179.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir --disable-pip-version-check "semgrep==${SEMGREP_VERSION}" \
 && /opt/semgrep/bin/pip uninstall -y pip \
 && /opt/semgrep/bin/semgrep --version

# ------------------------------------------------------------------------------------------------------------------------------------
# Tool bases (shared by the targets below).
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${ASPNET_IMAGE} AS scanner-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends apt git python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /opt/tools/bin/gitleaks /opt/tools/bin/trivy /usr/local/bin/
COPY --from=semgrep /opt/semgrep /opt/semgrep
ENV PATH="/opt/semgrep/bin:${PATH}" \
    HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_CONFIG_HOME=/tmp/.config \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 TRIVY_NO_PROGRESS=true \
    GIT_TERMINAL_PROMPT=0

FROM ${SDK_IMAGE} AS toolchain-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends apt libbrotli1 python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /opt/tools/bin/ /usr/local/bin/
COPY --from=semgrep /opt/semgrep /opt/semgrep
ENV PATH="/opt/semgrep/bin:${PATH}" \
    HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_CONFIG_HOME=/tmp/.config GH_CONFIG_DIR=/tmp/.config/gh \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 TRIVY_NO_PROGRESS=true GIT_TERMINAL_PROMPT=0 \
    DOTNET_CLI_HOME=/tmp NUGET_PACKAGES=/tmp/.nuget/packages DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_GENERATE_ASPNET_CERTIFICATE=false

# ------------------------------------------------------------------------------------------------------------------------------------
# Targets. Same layout in each: /app = content root (rules/, db/, deploy/agents.json), /app/bin = binaries, /data = state.
# AGENT_ROLE bakes the default SECAGENT_AGENT (the Bicep also sets it); one image per agent keeps tags/rollbacks per agent.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${CHISELED_IMAGE} AS runtime
ARG AGENT_ROLE=""
WORKDIR /app
COPY --from=content /content/ /app/
COPY --from=publish-worker /out/ /app/bin/
COPY --from=content --chown=1654:1654 /data-template/ /data/
ENV SECAGENT_AGENT=${AGENT_ROLE} SECAGENT_CONTENT_ROOT=/app SECAGENT_DATA_ROOT=/data ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_gcServer=0 DOTNET_EnableDiagnostics=0
USER 1654
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["dotnet", "/app/bin/secagent-worker.dll", "probe"]
ENTRYPOINT ["dotnet", "/app/bin/secagent-worker.dll"]

FROM scanner-base AS scanner
ARG AGENT_ROLE=scanner
WORKDIR /app
COPY --from=content /content/ /app/
COPY --from=publish-worker /out/ /app/bin/
COPY --from=content --chown=1654:1654 /data-template/ /data/
ENV SECAGENT_AGENT=${AGENT_ROLE} SECAGENT_CONTENT_ROOT=/app SECAGENT_DATA_ROOT=/data ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_gcServer=0 DOTNET_EnableDiagnostics=0
USER 1654
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["dotnet", "/app/bin/secagent-worker.dll", "probe"]
ENTRYPOINT ["dotnet", "/app/bin/secagent-worker.dll"]

FROM toolchain-base AS toolchain
ARG AGENT_ROLE=""
WORKDIR /app
COPY --from=content /content/ /app/
COPY --from=publish-worker /out/ /app/bin/
COPY --from=content --chown=1654:1654 /data-template/ /data/
ENV SECAGENT_AGENT=${AGENT_ROLE} SECAGENT_CONTENT_ROOT=/app SECAGENT_DATA_ROOT=/data ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_gcServer=0 DOTNET_EnableDiagnostics=0
USER 1654
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["dotnet", "/app/bin/secagent-worker.dll", "probe"]
ENTRYPOINT ["dotnet", "/app/bin/secagent-worker.dll"]

FROM toolchain-base AS dashboard
ARG AGENT_ROLE=agent-api
WORKDIR /app
COPY --from=content /content/ /app/
COPY --from=publish-dashboard /out/ /app/bin/
COPY --from=content --chown=1654:1654 /data-template/ /data/
ENV SECAGENT_AGENT=${AGENT_ROLE} SECAGENT_CONTENT_ROOT=/app SECAGENT_DATA_ROOT=/data SECAGENT_BIND_ADDRESS=0.0.0.0 SECAGENT_PORT=8795 \
    DOTNET_gcServer=0 DOTNET_EnableDiagnostics=0
USER 1654
EXPOSE 8795
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["curl", "-fsS", "http://127.0.0.1:8795/healthz"]
ENTRYPOINT ["dotnet", "/app/bin/secagent.dll", "serve"]
