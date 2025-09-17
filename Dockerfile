FROM python:3.11-slim

# Avoid interactive debconf prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update -yqq && apt-get install -yqq --no-install-recommends \
    git \
    npm \
    openjdk-21-jre-headless \
    golang-go \
    ruby \
    ruby-dev \
    build-essential \
    wget \
    curl \
    unzip \
    ca-certificates \
    gnupg \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Optional: provide a corporate root CA (Base64-encoded PEM) at build time to trust SSL interception proxies
# Usage: --build-arg CORP_CA_B64=$(base64 -w0 corp-root.pem)
ARG CORP_CA_B64=""

# Install Ruby gems (bundler-audit) with robust SSL handling
# 1) If CORP_CA_B64 is provided, install it and update CA bundle
# 2) Try a normal gem install
# 3) If it fails due to SSL, fall back to HTTP rubygems (insecure) as a last resort
RUN set -eux; \
    if [ -n "$CORP_CA_B64" ]; then \
      echo "$CORP_CA_B64" | base64 -d > /usr/local/share/ca-certificates/corp-root.crt; \
      update-ca-certificates || true; \
    fi; \
    gem update --system || true; \
    if ! gem install bundler-audit --no-document; then \
      echo "bundler-audit install failed, retrying with HTTP (insecure) source due to SSL inspection"; \
      gem sources --remove https://rubygems.org/ || true; \
      gem sources --add http://rubygems.org/ || true; \
      gem install bundler-audit --no-document --clear-sources --source http://rubygems.org/; \
    fi

# Install Go tools
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
ENV PATH="${PATH}:/root/go/bin"

# Install OWASP Dependency-Check (optional; keep for compatibility)
ENV DEPENDENCY_CHECK_VERSION=12.1.0
ENV DEPENDENCY_CHECK_URL=https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip
RUN echo "Downloading OWASP Dependency-Check ${DEPENDENCY_CHECK_VERSION}..." && \
    wget --no-check-certificate -q ${DEPENDENCY_CHECK_URL} -O /tmp/dependency-check.zip && \
    unzip -q /tmp/dependency-check.zip -d /opt/ && \
    rm /tmp/dependency-check.zip && \
    chmod +x /opt/dependency-check/bin/* && \
    /opt/dependency-check/bin/dependency-check.sh --version || true
ENV PATH="${PATH}:/opt/dependency-check/bin"

# Install Gitleaks
ENV GITLEAKS_VERSION=8.18.4
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz -O /tmp/gitleaks.tgz \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tgz \
    && gitleaks version || true

# Install Trivy via official installer (more robust across Debian variants)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy --version || true

# Install Syft and Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && syft version || true \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && grype version || true

# Install OSV-Scanner
ENV OSV_VERSION=1.7.3
RUN wget -q https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${OSV_VERSION}_linux_amd64 -O /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner \
    && osv-scanner --version || true

# Install CodeQL CLI
ENV CODEQL_VERSION=2.18.4
RUN wget -q https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip -O /tmp/codeql.zip \
    && unzip -q /tmp/codeql.zip -d /opt \
    && rm /tmp/codeql.zip
ENV PATH="${PATH}:/opt/codeql/codeql"

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m pip install --no-cache-dir semgrep

# Copy the rest of the application
COPY . .

# Create volumes for reports (multiple scanners)
VOLUME ["/app/ci_reports", \
        "/app/codeql_reports", \
        "/app/oss_reports", \
        "/app/secrets_reports", \
        "/app/hardcoded_ips_reports", \
        "/app/terraform_reports", \
        "/app/contributors_reports", \
        "/app/markdown", \
        "/app/logs"]

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Entrypoint: orchestrator (balanced by default)
ENTRYPOINT ["python", "orchestrate_scans.py", "--profile", "balanced"]
