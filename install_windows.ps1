# Windows Installation Script for AuditGH
# Run this script as Administrator

# Colors for output
$Green = '\033[0;32m'
$Yellow = '\033[1;33m'
$Red = '\033[0;31m'
$NoColor = '\033[0m'

function Write-ColorOutput($color, $message) {
    Write-Host -ForegroundColor $color $message
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-ColorOutput $Red "Please run this script as Administrator"
    exit 1
}

# Install Chocolatey if not installed
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Chocolatey package manager..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install Python if not installed
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Python..."
    choco install python3 -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install Git if not installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Git..."
    choco install git -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install Node.js if not installed (for npm audit)
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Node.js..."
    choco install nodejs-lts -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Install Go if not installed (for govulncheck)
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Go..."
    choco install golang -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    $env:GOPATH = [System.Environment]::GetEnvironmentVariable("GOPATH","User")
    if (-not $env:GOPATH) {
        $env:GOPATH = "$env:USERPROFILE\go"
        [System.Environment]::SetEnvironmentVariable("GOPATH", $env:GOPATH, "User")
    }
    $env:Path += ";$env:GOPATH\bin"
}

# Install Ruby if not installed (for bundle audit)
if (-not (Get-Command ruby -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Ruby..."
    choco install ruby -y
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    # Install bundler
    gem install bundler
}

# Install OWASP Dependency-Check if not installed
$depCheckPath = "C:\\Program Files\\DependencyCheck\\bin\\dependency-check.bat"
if (-not (Test-Path $depCheckPath)) {
    Write-ColorOutput $Yellow "Installing OWASP Dependency-Check..."
    choco install dependency-check -y
}

# Install Python dependencies
Write-ColorOutput $Yellow "Installing Python dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

# Install Semgrep if not installed
if (-not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing Semgrep..."
    python -m pip install semgrep
}

# Install govulncheck if not installed
if (-not (Get-Command govulncheck -ErrorAction SilentlyContinue)) {
    Write-ColorOutput $Yellow "Installing govulncheck..."
    go install golang.org/x/vuln/cmd/govulncheck@latest
}

Write-ColorOutput $Green "✓ All dependencies installed successfully!"
Write-ColorOutput $Green "Please restart your terminal for all changes to take effect."
