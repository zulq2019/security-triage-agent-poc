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

# ------------------------------------------------------------------------------------------------------------------------------------
# Build: restore (cached layer, only project files), then publish each host in its own stage so a target builds only what it needs.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${SDK_IMAGE} AS build
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
RUN --mount=type=cache,id=secagent-nuget,target=/root/.nuget/packages \
    dotnet restore src/SecAgent.Worker/SecAgent.Worker.csproj \
 && dotnet restore src/SecAgent.Dashboard/SecAgent.Dashboard.csproj
COPY src/ src/

FROM build AS publish-worker
RUN --mount=type=cache,id=secagent-nuget,target=/root/.nuget/packages \
    dotnet publish src/SecAgent.Worker/SecAgent.Worker.csproj -c Release -o /out --no-restore -p:UseAppHost=false

FROM build AS publish-dashboard
RUN --mount=type=cache,id=secagent-nuget,target=/root/.nuget/packages \
    dotnet publish src/SecAgent.Dashboard/SecAgent.Dashboard.csproj -c Release -o /out --no-restore -p:UseAppHost=false

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
# Scanner tools: release binaries pinned by version AND sha256 (from each release's checksums file). No install scripts, no `latest`.
# ------------------------------------------------------------------------------------------------------------------------------------
FROM ${SDK_IMAGE} AS tools
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
WORKDIR /tmp/tools
RUN case "${TARGETARCH:-amd64}" in \
      amd64) GL=x64;   TV=64bit; GA=amd64; GL_SHA=${GITLEAKS_SHA256_AMD64}; TV_SHA=${TRIVY_SHA256_AMD64}; GH_SHA=${GH_SHA256_AMD64} ;; \
      arm64) GL=arm64; TV=ARM64; GA=arm64; GL_SHA=${GITLEAKS_SHA256_ARM64}; TV_SHA=${TRIVY_SHA256_ARM64}; GH_SHA=${GH_SHA256_ARM64} ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/tools/bin; \
    curl -fsSLo gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz"; \
    echo "${GL_SHA}  gitleaks.tgz" | sha256sum -c -; \
    tar -xzf gitleaks.tgz -C /opt/tools/bin gitleaks; \
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
