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

ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317
ARG ASPNET_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0-noble@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4
ARG CHISELED_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:00e0ad6a7ef8c0c1391b87f05c7ac757a15740455688f2bfcd146a3f4b987efd
# Go toolchain only for rebuilding gitleaks (see the gitleaks stage). golang 1.26.8.
ARG GO_IMAGE=golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d

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
# built with Go 1.24.11 and old golang.org/x modules, and the image scan in CI fails on ~30 fixable HIGH/CRITICAL CVEs in it. Same
# gitleaks code; only the Go standard library and x/crypto, x/text (indirect deps) move to fixed versions. Cross-compiles for TARGETARCH.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS gitleaks
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SRC_SHA256=e90fb266d75837e75894c778bf594ab8e2787f12dce5a62651f21b893eaf9abb
ARG X_CRYPTO_VERSION=v0.55.0
ARG X_TEXT_VERSION=v0.41.0
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN --mount=type=cache,id=secagent-gomod,target=/go/pkg/mod \
    curl -fsSLo src.tgz "https://github.com/gitleaks/gitleaks/archive/refs/tags/v${GITLEAKS_VERSION}.tar.gz"; \
    echo "${GITLEAKS_SRC_SHA256}  src.tgz" | sha256sum -c -; \
    tar -xzf src.tgz --strip-components=1; \
    go get "golang.org/x/crypto@${X_CRYPTO_VERSION}" "golang.org/x/text@${X_TEXT_VERSION}"; \
    go mod tidy; \
    GOARCH="${TARGETARCH:-amd64}" go build -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=v${GITLEAKS_VERSION}" -o /out/gitleaks .

# ------------------------------------------------------------------------------------------------------------------------------------
# Other tools: release binaries pinned by version AND sha256 (from each release's checksums file). No install scripts, no `latest`.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${SDK_IMAGE} AS tools
ARG TARGETARCH
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
WORKDIR /tmp/tools
COPY --from=gitleaks /out/gitleaks /opt/tools/bin/gitleaks
RUN case "${TARGETARCH:-amd64}" in \
      amd64) TV=64bit; GA=amd64; TV_SHA=${TRIVY_SHA256_AMD64}; GH_SHA=${GH_SHA256_AMD64} ;; \
      arm64) TV=ARM64; GA=arm64; TV_SHA=${TRIVY_SHA256_ARM64}; GH_SHA=${GH_SHA256_ARM64} ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TV}.tar.gz"; \
    echo "${TV_SHA}  trivy.tgz" | sha256sum -c -; \
    tar -xzf trivy.tgz -C /opt/tools/bin trivy; \
    curl -fsSLo gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${GA}.tar.gz"; \
    echo "${GH_SHA}  gh.tgz" | sha256sum -c -; \
    tar -xzf gh.tgz --strip-components=2 -C /opt/tools/bin "gh_${GH_VERSION}_linux_${GA}/bin/gh"; \
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
 && apt-get install -y --no-install-recommends git python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /opt/tools/bin/gitleaks /opt/tools/bin/trivy /usr/local/bin/
COPY --from=semgrep /opt/semgrep /opt/semgrep
ENV PATH="/opt/semgrep/bin:${PATH}" \
    HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_CONFIG_HOME=/tmp/.config \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 TRIVY_NO_PROGRESS=true \
    GIT_TERMINAL_PROMPT=0

FROM ${SDK_IMAGE} AS toolchain-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
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
