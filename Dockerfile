FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    && rm -rf /var/lib/apt/lists/*

# Install Ruby gems
RUN gem install bundler-audit

# Install Go tools
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
ENV PATH="${PATH}:/root/go/bin"

# Install OWASP Dependency-Check
ENV DEPENDENCY_CHECK_VERSION=12.1.0
ENV DEPENDENCY_CHECK_URL=https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip

# Download and install Dependency-Check
RUN echo "Downloading OWASP Dependency-Check ${DEPENDENCY_CHECK_VERSION}..." && \
    wget --no-check-certificate -q ${DEPENDENCY_CHECK_URL} -O /tmp/dependency-check.zip && \
    unzip -q /tmp/dependency-check.zip -d /opt/ && \
    rm /tmp/dependency-check.zip && \
    chmod +x /opt/dependency-check/bin/* && \
    echo "Dependency-Check installed successfully" && \
    /opt/dependency-check/bin/dependency-check.sh --version

ENV PATH="${PATH}:/opt/dependency-check/bin"

# Configure git to use the token for authentication
ARG GITHUB_TOKEN
RUN git config --global credential.helper store && \
    echo "https://${GITHUB_TOKEN}:x-oauth-basic@github.com" > /root/.git-credentials && \
    chmod 600 /root/.git-credentials

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install semgrep
RUN python -m pip install semgrep

# Copy the rest of the application
COPY . .

# Create a volume for reports
VOLUME ["/app/vulnerability_reports"]

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Entrypoint
ENTRYPOINT ["python", "scan_repos.py"]
