#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Parse optional flags
SKIP_JAVA=0
SKIP_GO=0
SANITY_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-java)
      SKIP_JAVA=1
      shift ;;
    --no-go)
      SKIP_GO=1
      shift ;;
    --sanity-only)
      SANITY_ONLY=1
      shift ;;
    *)
      # ignore unknown flags
      shift ;;
  esac
done

# Sanity check function
sanity_check() {
  echo -e "${GREEN}Running post-install sanity checks...${NC}"
  # tool, display name, version args
  tools=(
    "git|Git|--version"
    "semgrep|Semgrep|--version"
    "gitleaks|Gitleaks|version"
    "bandit|Bandit|--version"
    "trivy|Trivy|--version"
    "syft|Syft|--version"
    "grype|Grype|--version"
    "dependency-check|OWASP Dependency-Check|--version"
    "checkov|Checkov|--version"
    "pip-audit|pip-audit|--version"
    "safety|Safety|--version"
    "npm|Node/NPM|--version"
    "go|Go|version"
    "ruby|Ruby|--version"
    "bundle-audit|bundler-audit|version"
    "govulncheck|govulncheck|--version"
    "java|Java|-version"
  )
  ok=0; missing=0
  for entry in "${tools[@]}"; do
    IFS='|' read -r bin label vflag <<< "$entry"
    if command_exists "$bin"; then
      # java prints to stderr
      ver=$("$bin" $vflag 2>&1 | head -n 1)
      echo -e "${GREEN}✓${NC} $label: $ver"
      ok=$((ok+1))
    else
      echo -e "${YELLOW}✗${NC} $label: not found"
      missing=$((missing+1))
    fi
  done
  echo -e "${GREEN}Sanity check complete${NC} — present: $ok, missing: $missing"
}

if [[ "$SANITY_ONLY" -eq 1 ]]; then
  sanity_check
  exit 0
fi

# Function to install on macOS
install_macos() {
    echo -e "${GREEN}Detected macOS${NC}"
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        echo -e "${YELLOW}Installing Homebrew...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH if not already there
        if [[ "$SHELL" == "/bin/zsh" ]]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    else
        echo -e "${GREEN}Homebrew is already installed${NC}"
    fi
    
    # Install required tools
    echo -e "${GREEN}Installing required tools...${NC}"
    
    # Install Semgrep
    if ! command_exists semgrep; then
        echo -e "${YELLOW}Installing Semgrep...${NC}"
        brew install semgrep
    else
        echo -e "${GREEN}Semgrep is already installed${NC}"
    fi
    
    # Core CLIs/runtimes commonly needed by scanners
    command_exists git || brew install git
    command_exists npm || brew install node
    if [[ "$SKIP_GO" -eq 0 ]]; then
        command_exists go || brew install go
    else
        echo -e "${YELLOW}Skipping Go installation (--no-go)${NC}"
    fi
    command_exists ruby || brew install ruby
    # Java (for dependency-check). Prefer Temurin/OpenJDK from Homebrew
    if [[ "$SKIP_JAVA" -eq 0 ]]; then
        if ! /usr/libexec/java_home >/dev/null 2>&1; then
            echo -e "${YELLOW}Installing OpenJDK (Temurin)...${NC}"
            brew install openjdk
            sudo ln -sfn /opt/homebrew/opt/openjdk/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk.jdk 2>/dev/null || true
        fi
    else
        echo -e "${YELLOW}Skipping Java installation (--no-java)${NC}"
    fi

    # Security scanners and helpers
    if ! command_exists gitleaks; then
        echo -e "${YELLOW}Installing Gitleaks...${NC}"
        brew install gitleaks
    fi
    if ! command_exists bandit; then
        echo -e "${YELLOW}Installing Bandit...${NC}"
        brew install bandit || pip3 install bandit
    fi
    if ! command_exists trivy; then
        echo -e "${YELLOW}Installing Trivy...${NC}"
        brew install trivy
    fi
    if ! command_exists syft; then
        echo -e "${YELLOW}Installing Syft...${NC}"
        brew install syft
    fi
    if ! command_exists grype; then
        echo -e "${YELLOW}Installing Grype...${NC}"
        brew install grype
    fi
    if ! command_exists dependency-check; then
        echo -e "${YELLOW}Installing OWASP Dependency-Check...${NC}"
        brew install dependency-check || true
    fi

    # Checkov via pip
    if ! command_exists checkov; then
        echo -e "${YELLOW}Installing Checkov...${NC}"
        pip3 install --upgrade checkov
    fi
    
    # Install Python dependencies
    if command_exists pip3; then
        echo -e "${YELLOW}Installing Python dependencies...${NC}"
        pip3 install -r requirements.txt
    else
        echo -e "${RED}pip3 not found. Please install Python 3 and pip3.${NC}"
        exit 1
    fi

    # Govulncheck (Go). This installs to GOPATH/bin; ensure it's on PATH
    if [[ "$SKIP_GO" -eq 0 ]] && command_exists go; then
        if ! command_exists govulncheck; then
            echo -e "${YELLOW}Installing govulncheck...${NC}"
            GO111MODULE=on go install golang.org/x/vuln/cmd/govulncheck@latest || true
            echo -e "${YELLOW}If govulncheck is not found, add \"$(go env GOPATH)/bin\" to your PATH.${NC}"
        fi
    fi

    # Ruby bundle-audit
    if command_exists ruby && command_exists gem; then
        if ! command_exists bundle-audit; then
            echo -e "${YELLOW}Installing bundler-audit...${NC}"
            gem install bundler-audit || true
        fi
    fi
    
    sanity_check
    echo -e "${GREEN}✓ All dependencies installed successfully!${NC}"
}

# Function to install on Linux
install_linux() {
    echo -e "${GREEN}Detected Linux${NC}"
    
    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Please run as root (use sudo)${NC}"
        exit 1
    fi
    
    # Detect package manager
    if command_exists apt-get; then
        # Debian/Ubuntu
        echo -e "${YELLOW}Updating package lists...${NC}"
        apt-get update
        
        # Install required system packages
        echo -e "${YELLOW}Installing system dependencies...${NC}"
        apt-get install -y python3-pip python3-venv git curl gnupg ca-certificates

        # Runtimes commonly needed
        # Optional: allow skipping Go/Java
        if [[ "$SKIP_GO" -eq 0 ]]; then
            apt-get install -y golang || true
        else
            echo -e "${YELLOW}Skipping Go installation (--no-go)${NC}"
        fi
        apt-get install -y nodejs npm ruby-full || true
        if [[ "$SKIP_JAVA" -eq 0 ]]; then
            apt-get install -y default-jre || true
        else
            echo -e "${YELLOW}Skipping Java installation (--no-java)${NC}"
        fi

        # Install Semgrep
        if ! command_exists semgrep; then
            echo -e "${YELLOW}Installing Semgrep...${NC}"
            python3 -m pip install --upgrade pip
            python3 -m pip install semgrep
        fi
        
        # CLI tools available via pip or vendor installers
        python3 -m pip install --upgrade bandit checkov pip-audit safety
        
        # Trivy (official script)
        if ! command_exists trivy; then
            echo -e "${YELLOW}Installing Trivy...${NC}"
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || true
        fi
        # Syft & Grype (Anchore script)
        if ! command_exists syft; then
            echo -e "${YELLOW}Installing Syft...${NC}"
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin || true
        fi
        if ! command_exists grype; then
            echo -e "${YELLOW}Installing Grype...${NC}"
            curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin || true
        fi
        # Gitleaks
        if ! command_exists gitleaks; then
            echo -e "${YELLOW}Installing Gitleaks...${NC}"
            curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_$(uname -m).tar.gz -o /tmp/gitleaks.tgz && \
            tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks || true
        fi
        # OWASP Dependency-Check (CLI)
        if ! command_exists dependency-check; then
            echo -e "${YELLOW}Installing OWASP Dependency-Check (zip)...${NC}"
            mkdir -p /opt && cd /opt && \
            curl -sSL https://github.com/jeremylong/DependencyCheck/releases/latest/download/dependency-check.zip -o dependency-check.zip && \
            unzip -q dependency-check.zip && ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check || true
        fi
        
    elif command_exists yum; then
        # RHEL/CentOS
        echo -e "${YELLOW}Installing dependencies...${NC}"
        yum install -y python3-pip git curl

        # Install Semgrep
        if ! command_exists semgrep; then
            echo -e "${YELLOW}Installing Semgrep...${NC}"
            python3 -m pip install --upgrade pip
            python3 -m pip install semgrep
        fi
        
        python3 -m pip install --upgrade bandit checkov pip-audit safety
        echo -e "${YELLOW}For trivy/syft/grype/gitleaks/dependency-check, please install via vendor scripts or your distro packages.${NC}"
    else
        echo -e "${RED}Unsupported package manager. Please install dependencies manually.${NC}"
        exit 1
    fi
    
    # Install Python dependencies
    echo -e "${YELLOW}Installing Python dependencies...${NC}"
    pip3 install -r requirements.txt
    sanity_check
    echo -e "${GREEN}✓ All dependencies installed successfully!${NC}"
}

# Function to install on Windows
install_windows() {
    echo -e "${GREEN}Detected Windows${NC}"
    
    # Check if running as administrator
    net session >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}Please run as Administrator${NC}"
        exit 1
    fi
    
    # Install Chocolatey if not installed
    if ! command_exists choco; then
        echo -e "${YELLOW}Installing Chocolatey package manager...${NC}"
        powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')); \$env:Path = [System.Environment]::GetEnvironmentVariable(\"Path\",\"Machine\") + \";\" + [System.Environment]::GetEnvironmentVariable(\"Path\",\"User\")"
    fi
    
    # Install Python if not installed
    if ! command_exists python; then
        echo -e "${YELLOW}Installing Python...${NC}"
        choco install python3 -y
        # Refresh PATH using PowerShell
        powershell -Command "\$env:Path = [System.Environment]::GetEnvironmentVariable(\"Path\",\"Machine\") + \";\" + [System.Environment]::GetEnvironmentVariable(\"Path\",\"User\")"
    fi
    
    # Install Semgrep if not installed
    if ! command_exists semgrep; then
        echo -e "${YELLOW}Installing Semgrep...${NC}"
        python -m pip install --upgrade pip
        python -m pip install semgrep
    fi
    
    # Core tools via Chocolatey (if available)
    if command_exists choco; then
        choco install -y git golang nodejs ruby openjdk || true
        choco install -y gitleaks trivy || true
    fi
    
    # Python-based scanners
    pip install -U bandit checkov pip-audit safety
    
    echo -e "${YELLOW}For Syft/Grype on Windows, download releases from Anchore or use Chocolatey if packages are available.${NC}"
    
    # Install Python dependencies
    echo -e "${YELLOW}Installing Python dependencies...${NC}"
    pip install -r requirements.txt
    sanity_check
    echo -e "${GREEN}✓ All dependencies installed successfully!${NC}"
}

# Detect OS and run appropriate installer
case "$(uname -s)" in
    Darwin)
        install_macos
        ;;
    Linux)
        install_linux
        ;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*)
        install_windows
        ;;
    *)
        echo -e "${RED}Unsupported operating system. Please install dependencies manually.${NC}"
        exit 1
        ;;
esac
