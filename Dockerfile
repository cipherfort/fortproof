# SPDX-License-Identifier: Apache-2.0
# FortProof: one image, three processes (aap api | aap hook | aap worker), plus jobs.
# Base images pinned by digest; gh (attestation verification backend for private repos) built from a pinned commit.
# Built, scanned and attested by .github/workflows/release.yml; runs as an unprivileged user with a read-only root.

FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.13@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS backend
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock backend/README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/src ./src
COPY backend/migrations ./migrations
COPY backend/alembic.ini ./
RUN uv sync --frozen --no-dev

# gh v2.102.0 (the latest release) is built from its tagged commit with golang.org/x/net raised to 0.60.0: the upstream
# binary carries x/net 0.58.0, with fixable HIGH CVEs (CVE-2026-78669 and others) that fail the release scan. Go back to
# the upstream binary once cli/cli ships a release with the fix. Go 1.27.2 (not the 1.27.1 the release used) fixes
# twelve standard-library vulnerabilities in net/http, crypto/tls and html/template. Cross-compiled, static, no cgo.
# The tag is checked out (and its commit checked) so Go stamps the module version v2.102.0+dirty; from a bare commit
# it stamps a v2.0.0 pseudo-version, which scanners match against every gh CVE since 2.0.
FROM --platform=$BUILDPLATFORM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS gh
ARG GH_VERSION=2.102.0
ARG GH_COMMIT=fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
WORKDIR /src
RUN git init -q . && git remote add origin https://github.com/cli/cli.git \
 && git fetch -q --depth 1 origin tag "v$GH_VERSION" && git checkout -q "v$GH_VERSION" \
 && test "$(git rev-parse HEAD)" = "$GH_COMMIT" \
 && go get golang.org/x/net@v0.60.0 && go mod tidy \
 && GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build \
      -ldflags "-s -w -X github.com/cli/cli/v2/internal/build.Version=${GH_VERSION}" -o /out/gh ./cmd/gh

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin aap
COPY --from=gh /out/gh /usr/local/bin/gh
COPY --from=backend /app/backend /app/backend
COPY --from=ui /src/frontend/dist /app/frontend/dist
# governed configuration, catalogue and schemas are part of the release (config versions are content-addressed)
COPY catalogue /app/catalogue
COPY config /app/config
COPY schemas /app/schemas
COPY templates /app/templates
COPY pipelines /app/pipelines
# the licence travels with the released image (OpenSSF Baseline OSPS-LE-03.02)
COPY LICENSE NOTICE /app/
LABEL org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cipherfort/fortproof"
ENV PATH=/app/backend/.venv/bin:$PATH AAP_REPO_ROOT=/app AAP_STATIC_DIR=/app/frontend/dist \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
WORKDIR /app
EXPOSE 8000 8001
HEALTHCHECK NONE
CMD ["aap", "api", "--host", "0.0.0.0", "--port", "8000"]
