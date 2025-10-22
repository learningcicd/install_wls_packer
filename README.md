
## Setup Guide

### Create configure-disk-mounts.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Configurable targets (GiB/TiB in bytes) ---
SWAP_TARGET_BYTES=34359738368        # 32 GiB
ORACLE_TARGET_BYTES=107374182400     # 100 GiB
SHARED_TARGET_BYTES=107374182400     # 100 GiB (change to 1099511627776 for 1TB)

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (sudo)." >&2
    exit 1
  fi
}

has_children() {
  local dev="$1"
  # If lsblk shows more than one line (disk + parts), it has children
  [[ $(lsblk -n -o NAME "/dev/$dev" | wc -l) -gt 1 ]]
}

find_unpartitioned_disks() {
  # Prints: "<name> <size_bytes>"
  lsblk -dn -o NAME,TYPE,SIZE -b | awk '$2=="disk"{print $1" "$3}' | while read -r name size; do
    if ! has_children "$name"; then
      echo "$name $size"
    fi
  done
}

ensure_pkg() {
  local bin="$1" pkg_hint="$2"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Warning: '$bin' not found. Please install ($pkg_hint) and re-run." >&2
    exit 1
  fi
}

append_fstab_once() {
  local line="$1"
  local file="/etc/fstab"
  if ! grep -Fq "$line" "$file"; then
    echo "$line" >> "$file"
    echo "Appended to $file: $line"
  else
    echo "Entry already present in $file"
  fi
}

is_approx_equal() {
  local actual="$1"
  local target="$2"
  local tolerance_percent=2 # 2% tolerance

  local lower_bound=$(( target - (target * tolerance_percent / 100) ))
  local upper_bound=$(( target + (target * tolerance_percent / 100) ))

  [[ "$actual" -ge "$lower_bound" && "$actual" -le "$upper_bound" ]]
}

setup_swap_on_disk() {
  local dev="/dev/$1"
  echo "==> Configuring SWAP on $dev"
  ensure_pkg blkid "util-linux (blkid)"
  ensure_pkg swapon "util-linux (swapon/mkswap)"

  # If already has a swap signature, great; otherwise write one
  if ! blkid -t TYPE=swap "$dev" >/dev/null 2>&1; then
    echo "Creating swap signature on $dev ..."
    mkswap -f "$dev"
  else
    echo "$dev already has swap signature."
  fi

  local uuid
  uuid=$(blkid -s UUID -o value "$dev")
  if [[ -z "${uuid:-}" ]]; then
    echo "Error: could not read UUID for $dev" >&2
    exit 1
  fi

  # fstab entry for swap (no mountpoint, 'none' is conventional)
  local fstab_line="UUID=$uuid none swap sw,pri=10 0 0"
  append_fstab_once "$fstab_line"

  echo "Enabling swap..."
  swapon -a || true
  swapon --show || true
}

setup_oracle_on_disk() {
  local dev="/dev/$1"
  local mnt="/oracle"
  echo "==> Configuring /oracle on $dev"

  ensure_pkg blkid "util-linux (blkid)"
  # Prefer XFS for Oracle; fallback to ext4 if xfsprogs not present
  local fs="xfs"
  if ! command -v mkfs.xfs >/dev/null 2>&1; then
    echo "mkfs.xfs not found; will use ext4 instead. (Install 'xfsprogs' to use XFS.)"
    fs="ext4"
  fi

  # If already has FS, skip mkfs
  if ! blkid -t TYPE="$fs" "$dev" >/dev/null 2>&1; then
    # If it has *some* filesystem, don't clobber silently
    if blkid "$dev" >/dev/null 2>&1; then
      echo "Error: $dev already has a filesystem. Refusing to overwrite." >&2
      exit 1
    fi
    echo "Creating $fs filesystem on $dev ..."
    if [[ "$fs" == "xfs" ]]; then
      mkfs.xfs -f "$dev"
    else
      mkfs.ext4 -F "$dev"
    fi
  else
    echo "$dev already formatted as $fs."
  fi

  mkdir -p "$mnt"
  local uuid
  uuid=$(blkid -s UUID -o value "$dev")
  if [[ -z "${uuid:-}" ]]; then
    echo "Error: could not read UUID for $dev" >&2
    exit 1
  fi

  # Reasonable defaults
  local opts="defaults,noatime,nofail"
  local passno="2"
  local fstab_line="UUID=$uuid $mnt $fs $opts 0 $passno"
  append_fstab_once "$fstab_line"

  echo "Mounting $mnt ..."
  mount -a
  df -h | grep -E "Filesystem|$mnt" || true
}

setup_shared_on_disk() {
  local dev="/dev/$1"
  local mnt="/domains"
  echo "==> Configuring shared volume on $dev at $mnt"

  ensure_pkg blkid "util-linux (blkid)"
  
  # Use ext4 for shared disk (better compatibility across multiple VMs)
  local fs="ext4"

  # Check if running in non-interactive mode (default to first VM behavior)
  local is_first="${SHARED_DISK_FIRST_VM:-yes}"
  
  # Only prompt if running interactively
  if [ -t 0 ]; then
    read -p "Is this the FIRST VM to setup this shared disk? (yes/no) [default: yes]: " user_input
    is_first="${user_input:-yes}"
  fi
  
  if [[ "$is_first" == "yes" ]]; then
    # First node: create filesystem
    if ! blkid -t TYPE="$fs" "$dev" >/dev/null 2>&1; then
      # If it has *some* filesystem, don't clobber silently
      if blkid "$dev" >/dev/null 2>&1; then
        echo "Warning: $dev already has a filesystem."
        if [ -t 0 ]; then
          read -p "Overwrite? This will DESTROY all data! (yes/no): " confirm
        else
          # In non-interactive mode, check environment variable
          confirm="${SHARED_DISK_OVERWRITE:-no}"
        fi
        if [[ "$confirm" != "yes" ]]; then
          echo "Skipping filesystem creation." >&2
          return
        fi
      fi
      echo "Creating $fs filesystem on $dev ..."
      mkfs.ext4 -F "$dev"
    else
      echo "$dev already formatted as $fs."
    fi
  else
    echo "Skipping filesystem creation (not first VM)."
    # Verify the disk has a filesystem
    if ! blkid "$dev" >/dev/null 2>&1; then
      echo "Error: $dev has no filesystem. Run this on the first VM first!" >&2
      exit 1
    fi
  fi

  mkdir -p "$mnt"
  local uuid
  uuid=$(blkid -s UUID -o value "$dev")
  if [[ -z "${uuid:-}" ]]; then
    echo "Error: could not read UUID for $dev" >&2
    exit 1
  fi

  # Mount options for shared disk
  # Note: For true concurrent access, you'd need a cluster filesystem (GFS2/OCFS2)
  # This basic setup is for sequential access or read-only sharing
  local opts="defaults,noatime,nofail"
  local passno="2"
  local fstab_line="UUID=$uuid $mnt $fs $opts 0 $passno"
  append_fstab_once "$fstab_line"

  echo "Mounting $mnt ..."
  mount -a
  df -h | grep -E "Filesystem|$mnt" || true
  
  # Set proper permissions for Oracle/application use
  echo "Setting permissions on $mnt ..."
  if id oracle >/dev/null 2>&1; then
    chown -R oracle:oracle "$mnt"
    chmod 777 "$mnt"
    echo "Set ownership to oracle:oracle with 777 permissions"
  else
    # If no oracle user, set to root and make it world-writable
    chown -R root:root "$mnt"
    chmod 777 "$mnt"
    echo "Set ownership to root:root with 777 permissions (no oracle user found)"
  fi
  
  echo ""
  echo "IMPORTANT: This shared disk is configured with standard ext4."
  echo "For concurrent write access from multiple VMs, consider:"
  echo "  - GFS2 (Global File System 2) with cluster setup"
  echo "  - OCFS2 (Oracle Cluster File System 2)"
  echo "  - Azure Files NFS share"
  echo "Current setup is suitable for:"
  echo "  - Read-only sharing across VMs"
  echo "  - Sequential access (one VM at a time)"
  echo ""
}

main() {
  require_root

  local swap_dev=""
  local oracle_dev=""
  local shared_dev=""

  echo "Scanning for unpartitioned disks..."
  while read -r name size; do
    echo "checking /dev/$name with size $size"
    # size is in bytes
    if is_approx_equal "$size" "$SWAP_TARGET_BYTES" && [[ -z "$swap_dev" ]]; then
      swap_dev="$name"
    elif is_approx_equal "$size" "$ORACLE_TARGET_BYTES" && [[ -z "$oracle_dev" ]]; then
      oracle_dev="$name"
    elif is_approx_equal "$size" "$SHARED_TARGET_BYTES" && [[ -z "$shared_dev" ]]; then
      shared_dev="$name"
    fi
  done < <(find_unpartitioned_disks)

  echo "Candidates:"
  echo "  Swap    (32GiB):  ${swap_dev:-<none found>}"
  echo "  Oracle (100GiB):  ${oracle_dev:-<none found>}"
  echo "  Shared (100GiB):  ${shared_dev:-<none found>}"

  if [[ -z "${swap_dev:-}" ]]; then
    echo "Warning: No unpartitioned 32GiB disk found." >&2
  else
    setup_swap_on_disk "$swap_dev"
  fi

  if [[ -z "${oracle_dev:-}" ]]; then
    echo "Warning: No unpartitioned 100GiB disk found." >&2
  else
    setup_oracle_on_disk "$oracle_dev"
  fi

  if [[ -z "${shared_dev:-}" ]]; then
    echo "Warning: No unpartitioned 1TiB disk found." >&2
  else
    setup_shared_on_disk "$shared_dev"
  fi

  echo "Done."
}

main "$@"

```

### Create configure_ownership.sh

```bash
#!/bin/bash
set -e

# Create group oracle if it doesn't exist
if ! getent group oracle >/dev/null; then
    groupadd oracle
    echo "Group 'oracle' created."
else
    echo "Group 'oracle' already exists."
fi

# Create user oracle if it doesn't exist
if ! id oracle >/dev/null 2>&1; then
    useradd -g oracle -m -s /bin/bash oracle
    echo "User 'oracle' created."
else
    echo "User 'oracle' already exists."
fi

# Add oracle user to root group
if ! groups oracle | grep -q "\broot\b"; then
    usermod -a -G root oracle
    echo "User 'oracle' added to root group."
else
    echo "User 'oracle' is already a member of root group."
fi

# Add oracle user to sudoers
if ! grep -q "^oracle" /etc/sudoers && ! [ -f /etc/sudoers.d/oracle ]; then
    echo "oracle ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/oracle
    chmod 440 /etc/sudoers.d/oracle
    echo "User 'oracle' added to sudoers with NOPASSWD access."
elif [ -f /etc/sudoers.d/oracle ]; then
    echo "User 'oracle' sudoers file already exists."
elif grep -q "^oracle" /etc/sudoers; then
    echo "User 'oracle' already has sudo access in /etc/sudoers."
fi

# Ensure the /oracle directory exists
if [ ! -d "/oracle" ]; then
    mkdir -p /oracle
    echo "/oracle directory created."
fi

# Change ownership to oracle:oracle
chown -R oracle:oracle /oracle
echo "Ownership of /oracle changed to oracle:oracle."

# Set permissions to 755
chmod 755 /oracle
echo "Permissions of /oracle set to 755."

# Ensure the /domain directory exists
if [ ! -d "/domains" ]; then
    mkdir -p /domain
    echo "/domains directory created."
fi

# Change ownership to oracle:oracle
chown -R oracle:oracle /domains
echo "Ownership of /domains changed to oracle:oracle."

# Set permissions to 755
chmod 755 /domains
echo "Permissions of /domains set to 755."
```

### Create create-folder.sh

```bash
#!/bin/bash 
# Script to create a folder under /usr and password file
# Folder name: wls-install-recipes
# Sets permissions to 755 and ownership to oracle:oracle
# Creates wls_password.txt with content "Welcome1"

# Check if user has root privileges
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root or use sudo."
   exit 1
fi

# Define the folder path
FOLDER_PATH="/usr/wls-install-recepies"

# Check if the folder already exists
if [[ -d "$FOLDER_PATH" ]]; then
    echo "The folder '$FOLDER_PATH' already exists."
else
    # Create the folder
    mkdir "$FOLDER_PATH"
    echo "The folder '$FOLDER_PATH' has been created successfully."
fi

# Change permissions to 755
chmod 755 "$FOLDER_PATH"
echo "Permissions for '$FOLDER_PATH' have been set to 755."

# Change ownership to oracle:oracle
chown oracle:oracle "$FOLDER_PATH"
echo "Ownership for '$FOLDER_PATH' has been set to oracle:oracle."

# Define the password file path
PASSWORD_FILE="$FOLDER_PATH/wls_password.txt"

# Create the password file with content "Welcome1"
echo "Welcome1" > "$PASSWORD_FILE"
echo "Password file '$PASSWORD_FILE' has been created successfully."

# Set appropriate permissions for the password file (600 for security)
chmod 600 "$PASSWORD_FILE"
echo "Permissions for '$PASSWORD_FILE' have been set to 600 (read/write for owner only)."

# Set ownership for the password file to oracle:oracle
chown oracle:oracle "$PASSWORD_FILE"
echo "Ownership for '$PASSWORD_FILE' has been set to oracle:oracle."
```

### Create download_packages.sh
```bash 
#!/usr/bin/env bash
# download_install_bin_sp.sh
set -euo pipefail

DEST="/usr/wls-install-recepies/install-bin"
ACCOUNT="wlsartifact"
CONTAINER="software"
PREFIX=""
DO_CHOWN="oracle:oracle"
DO_CHMOD="755"

usage(){ echo "Usage: sudo bash $0 --account <storageAccount> --container <container> [--prefix path/]"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --account) ACCOUNT="${2:-}"; shift 2 ;;
    --container) CONTAINER="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --chown) DO_CHOWN="${2:-}"; shift 2 ;;
    --chmod) DO_CHMOD="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

[[ -n "$ACCOUNT" && -n "$CONTAINER" ]] || { echo "ERROR: --account and --container required"; usage; }

# Network connectivity check function
check_connectivity() {
  echo "🔍 Checking network connectivity..."
  
  # Test basic internet connectivity
  if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "ERROR: No internet connectivity. Please check your network connection."
    exit 1
  fi
  
  # Test DNS resolution
  if ! nslookup login.microsoftonline.com >/dev/null 2>&1; then
    echo "ERROR: Cannot resolve Azure DNS names. Checking DNS settings..."
    echo "Current DNS servers:"
    cat /etc/resolv.conf
    echo "Consider adding public DNS servers like 8.8.8.8 or 1.1.1.1"
    exit 1
  fi
  
  # Test Azure endpoints
  local endpoints=(
    "login.microsoftonline.com"
    "${ACCOUNT}.blob.core.windows.net"
  )
  
  for endpoint in "${endpoints[@]}"; do
    if ! curl -s --connect-timeout 5 "https://${endpoint}" >/dev/null 2>&1; then
      echo "WARNING: Cannot reach ${endpoint}. This may cause authentication issues."
    else
      echo "✅ Can reach ${endpoint}"
    fi
  done
}

# Load creds and configuration
[[ -f "/tmp/.env" ]] || { echo "ERROR: /tmp/.env not found"; exit 1; }
# shellcheck disable=SC1091
source /tmp/.env
: "${AZ_TENANT_ID:?Missing AZ_TENANT_ID in /tmp/.env}"
: "${AZ_CLIENT_ID:?Missing AZ_CLIENT_ID in /tmp/.env}"
: "${AZ_CLIENT_SECRET:?Missing AZ_CLIENT_SECRET in /tmp/.env}"
# AZ_SUBSCRIPTION_ID is optional

# Apply Python warnings setting if specified in /tmp/.env
[[ -n "${PYTHONWARNINGS:-}" ]] && {
  echo "📝 Applying PYTHONWARNINGS from /tmp/.env: $PYTHONWARNINGS"
  export PYTHONWARNINGS
}

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }

# Run connectivity check
check_connectivity

mkdir -p "$DEST"; chmod "$DO_CHMOD" "$DEST"; chown "$DO_CHOWN" "$DEST" || true

install_azcli(){
  command -v az >/dev/null && return
  echo "Installing Azure CLI..."
  if command -v apt-get >/dev/null; then
    apt-get update -y
    apt-get install -y ca-certificates curl apt-transport-https lsb-release gnupg dnsutils
    # Ensure certificates are up to date
    update-ca-certificates
    curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor >/etc/apt/trusted.gpg.d/microsoft.gpg
    codename="$(lsb_release -cs || echo jammy)"
    echo "deb [arch=$(dpkg --print-architecture)] https://packages.microsoft.com/repos/azure-cli/ ${codename} main" >/etc/apt/sources.list.d/azure-cli.list
    apt-get update -y && apt-get install -y azure-cli
  elif command -v dnf >/dev/null; then
    dnf install -y ca-certificates bind-utils curl
    update-ca-trust
    rpm --import https://packages.microsoft.com/keys/microsoft.asc
    cat >/etc/yum.repos.d/azure-cli.repo <<'REPO'
[azure-cli]
name=Azure CLI
baseurl=https://packages.microsoft.com/yumrepos/azure-cli
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
REPO
    dnf install -y azure-cli
  elif command -v yum >/dev/null; then
    yum install -y ca-certificates bind-utils curl
    update-ca-trust
    rpm --import https://packages.microsoft.com/keys/microsoft.asc
    cat >/etc/yum.repos.d/azure-cli.repo <<'REPO'
[azure-cli]
name=Azure CLI
baseurl=https://packages.microsoft.com/yumrepos/azure-cli
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
REPO
    yum install -y azure-cli
  elif command -v zypper >/dev/null; then
    zypper --non-interactive install ca-certificates bind-utils curl
    update-ca-trust
    rpm --import https://packages.microsoft.com/keys/microsoft.asc
    zypper --non-interactive addrepo --refresh https://packages.microsoft.com/yumrepos/azure-cli azure-cli
    zypper --non-interactive refresh
    zypper --non-interactive install azure-cli
  else
    echo "Unsupported distro. Install az CLI manually."; exit 2
  fi
}
install_azcli

# Configure SSL/TLS and certificate handling
configure_ssl() {
  echo "🔒 Configuring SSL certificates..."
  
  # Update CA certificates
  if command -v update-ca-certificates >/dev/null; then
    update-ca-certificates >/dev/null 2>&1 || true
  elif command -v update-ca-trust >/dev/null; then
    update-ca-trust >/dev/null 2>&1 || true
  fi
  
  # Set Azure CLI SSL configuration
  export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=0
  export PYTHONHTTPSVERIFY=1
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  
  # Alternative paths for different distros
  if [[ ! -f "$REQUESTS_CA_BUNDLE" ]]; then
    for ca_bundle in "/etc/ssl/certs/ca-bundle.crt" "/etc/pki/tls/certs/ca-bundle.crt" "/etc/ssl/ca-bundle.pem"; do
      if [[ -f "$ca_bundle" ]]; then
        export REQUESTS_CA_BUNDLE="$ca_bundle"
        break
      fi
    done
  fi
  
  # Suppress only the urllib3 warning, not disable verification
  export PYTHONWARNINGS="ignore:Unverified HTTPS request"
}

echo "🔑 Logging in (allow-no-subscriptions)…"
# Add retry logic and better error handling
for attempt in 1 2 3; do
  echo "Login attempt $attempt/3..."
  if az login --service-principal \
    --username "$AZ_CLIENT_ID" \
    --password "$AZ_CLIENT_SECRET" \
    --tenant "$AZ_TENANT_ID" \
    --allow-no-subscriptions >/dev/null 2>&1; then
    echo "✅ Login successful"
    break
  else
    echo "❌ Login attempt $attempt failed"
    if [[ $attempt -eq 3 ]]; then
      echo "ERROR: All login attempts failed. Please check:"
      echo "1. Network connectivity to Azure"
      echo "2. Service principal credentials"
      echo "3. Tenant ID is correct"
      echo "4. DNS resolution is working"
      exit 1
    fi
    sleep 5
  fi
done

[[ -n "${AZ_SUBSCRIPTION_ID:-}" ]] && {
  echo "Setting subscription to ${AZ_SUBSCRIPTION_ID}..."
  az account set --subscription "$AZ_SUBSCRIPTION_ID" >/dev/null 2>&1 || true
}

# Sanity checks with better error handling
echo "🔎 Checking container and listing blobs…"
if ! az storage container show --name "$CONTAINER" --account-name "$ACCOUNT" --auth-mode login >/dev/null 2>&1; then
  echo "ERROR: Cannot access container '$CONTAINER' in storage account '$ACCOUNT'"
  echo "Please verify:"
  echo "1. Storage account name is correct"
  echo "2. Container exists"
  echo "3. Service principal has proper permissions (Storage Blob Data Reader/Contributor)"
  echo "4. Network allows access to ${ACCOUNT}.blob.core.windows.net"
  exit 1
fi

BLOB_COUNT=$(az storage blob list \
  --container-name "$CONTAINER" \
  --account-name "$ACCOUNT" \
  --auth-mode login \
  ${PREFIX:+--prefix "$PREFIX"} \
  --query 'length(@)' -o tsv 2>/dev/null || echo 0)
echo "Found ${BLOB_COUNT} blobs under ${CONTAINER}/${PREFIX:-}"

if [[ "$BLOB_COUNT" -eq 0 ]]; then
  echo "WARNING: No blobs found. Check the prefix path if specified."
fi

# Download with better error handling
echo "⬇️  Downloading blobs from ${ACCOUNT}/${CONTAINER} → ${DEST} …"
if ! az storage blob download-batch \
  --destination "$DEST" \
  --source "$CONTAINER" \
  --account-name "$ACCOUNT" \
  --auth-mode login \
  ${PREFIX:+--pattern "${PREFIX}*"} \
  --no-progress; then
  echo "ERROR: Download failed. Check network connectivity and permissions."
  exit 1
fi

chmod -R "$DO_CHMOD" "$DEST" || true
chown -R "$DO_CHOWN" "$DEST" || true
echo "✅ All blobs downloaded to ${DEST}"
```

#### Create fs_mount.sh
``` bash
#!/bin/bash

# Azure File Share Mount Script
# This script mounts an Azure file share to a local mount point
# Usage: ./script.sh [--auto-fstab] [mount_point]

set -e

# Parse command line arguments
AUTO_FSTAB=true  # Default to true for automation
for arg in "$@"; do
    case $arg in
        --auto-fstab)
            AUTO_FSTAB=true
            shift
            ;;
        --interactive)
            AUTO_FSTAB=false
            shift
            ;;
    esac
done

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Load creds and configuration
[[ -f "${CREDENTIAL_ENV:-/tmp/.env}" ]] || { log_error ".env not found"; exit 1; }
# shellcheck disable=SC1091
source "${CREDENTIAL_ENV:-/tmp/.env}"

# Validate required environment variables
REQUIRED_VARS=("AZ_TENANT_ID" "AZ_CLIENT_ID" "AZ_CLIENT_SECRET" "AZ_SUBSCRIPTION_ID" "AZURE_FS_ENDPOINT")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        log_error "Required environment variable $var is not set"
        exit 1
    fi
done

log_info "All required environment variables loaded successfully"

# Parse Azure File Share endpoint
# Expected format: https://<storage-account>.file.core.windows.net/<share-name>
STORAGE_ACCOUNT=$(echo $AZURE_FS_ENDPOINT | sed -n 's/.*https:\/\/\([^.]*\).*/\1/p')
SHARE_NAME=$(echo $AZURE_FS_ENDPOINT | sed -n 's/.*\.net\/\(.*\)/\1/p')

if [ -z "$STORAGE_ACCOUNT" ] || [ -z "$SHARE_NAME" ]; then
    log_error "Failed to parse AZURE_FS_ENDPOINT. Expected format: https://<storage-account>.file.core.windows.net/<share-name>"
    exit 1
fi

log_info "Storage Account: $STORAGE_ACCOUNT"
log_info "Share Name: $SHARE_NAME"

# Default mount point
MOUNT_POINT="/appconfig"
if [ ! -z "$1" ]; then
    MOUNT_POINT="$1"
fi

log_info "Mount point: $MOUNT_POINT"

# Check if cifs-utils is installed
if ! command -v mount.cifs &> /dev/null; then
    log_warning "cifs-utils not found. Installing..."
    if [ -f /etc/redhat-release ]; then
        sudo yum install -y cifs-utils
    elif [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y cifs-utils
    else
        log_error "Unsupported Linux distribution. Please install cifs-utils manually."
        exit 1
    fi
fi

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    log_error "Azure CLI is not installed. Please install it first."
    log_info "Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Login to Azure using service principal
log_info "Logging in to Azure..."
az login --service-principal \
    --username "$AZ_CLIENT_ID" \
    --password "$AZ_CLIENT_SECRET" \
    --tenant "$AZ_TENANT_ID" > /dev/null 2>&1

if [ $? -ne 0 ]; then
    log_error "Failed to login to Azure"
    exit 1
fi

log_info "Successfully logged in to Azure"

# Set subscription
az account set --subscription "$AZ_SUBSCRIPTION_ID"

# Get storage account key
log_info "Retrieving storage account key..."

# First, check if the storage account exists and get its resource group
STORAGE_ACCOUNT_INFO=$(az storage account list --query "[?name=='$STORAGE_ACCOUNT']" --output json 2>/dev/null)

if [ -z "$STORAGE_ACCOUNT_INFO" ] || [ "$STORAGE_ACCOUNT_INFO" == "[]" ]; then
    log_error "Storage account '$STORAGE_ACCOUNT' not found in subscription '$AZ_SUBSCRIPTION_ID'"
    log_error "Possible reasons:"
    log_error "  1. Storage account doesn't exist"
    log_error "  2. Service principal doesn't have Reader permissions on the storage account"
    log_error "  3. Storage account is in a different subscription"
    log_info "Listing all accessible storage accounts..."
    az storage account list --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location}" --output table
    exit 1
fi

RESOURCE_GROUP=$(echo "$STORAGE_ACCOUNT_INFO" | grep -o '"resourceGroup": "[^"]*' | cut -d'"' -f4)
log_info "Found storage account in resource group: $RESOURCE_GROUP"

STORAGE_KEY=$(az storage account keys list \
    --account-name "$STORAGE_ACCOUNT" \
    --resource-group "$RESOURCE_GROUP" \
    --query "[0].value" \
    --output tsv 2>&1)

if [ $? -ne 0 ] || [ -z "$STORAGE_KEY" ]; then
    log_error "Failed to retrieve storage account key"
    log_error "Error: $STORAGE_KEY"
    log_error "Ensure the service principal has 'Storage Account Key Operator Service Role' or 'Storage Account Contributor' role"
    exit 1
fi

log_info "Storage account key retrieved successfully"

# Create mount point directory if it doesn't exist
if [ ! -d "$MOUNT_POINT" ]; then
    log_info "Creating mount point directory: $MOUNT_POINT"
    sudo mkdir -p "$MOUNT_POINT"
fi

# Check if already mounted
if mountpoint -q "$MOUNT_POINT"; then
    log_warning "Mount point $MOUNT_POINT is already mounted"
    if [ "$AUTO_FSTAB" = false ]; then
        read -p "Do you want to unmount and remount? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Unmounting $MOUNT_POINT"
            sudo umount "$MOUNT_POINT"
        else
            log_info "Exiting without changes"
            exit 0
        fi
    else
        log_info "Auto mode: Unmounting $MOUNT_POINT"
        sudo umount "$MOUNT_POINT"
    fi
fi

# Check if oracle user exists
if ! id oracle &>/dev/null; then
    log_warning "Oracle user does not exist. Mounting without specific ownership."
    MOUNT_OPTIONS="vers=3.0,username=$STORAGE_ACCOUNT,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777,serverino"
    FSTAB_OPTIONS="nofail,vers=3.0,username=$STORAGE_ACCOUNT,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777,serverino"
else
    log_info "Mounting with oracle:oracle ownership"
    ORACLE_UID=$(id -u oracle)
    ORACLE_GID=$(id -g oracle)
    MOUNT_OPTIONS="vers=3.0,username=$STORAGE_ACCOUNT,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777,serverino,uid=$ORACLE_UID,gid=$ORACLE_GID"
    FSTAB_OPTIONS="nofail,vers=3.0,username=$STORAGE_ACCOUNT,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777,serverino,uid=$ORACLE_UID,gid=$ORACLE_GID"
fi

# Mount the Azure file share
log_info "Mounting Azure file share..."
sudo mount -t cifs \
    "//$STORAGE_ACCOUNT.file.core.windows.net/$SHARE_NAME" \
    "$MOUNT_POINT" \
    -o "$MOUNT_OPTIONS"

if [ $? -eq 0 ]; then
    log_info "Azure file share mounted successfully at $MOUNT_POINT"
    
    # Add to /etc/fstab for persistent mount
    if [ "$AUTO_FSTAB" = true ]; then
        FSTAB_ENTRY="//$STORAGE_ACCOUNT.file.core.windows.net/$SHARE_NAME $MOUNT_POINT cifs nofail,vers=3.0,username=$STORAGE_ACCOUNT,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777,serverino,uid=$(id -u oracle),gid=$(id -g oracle) 0 0"
        
        # Check if entry already exists
        if grep -q "$MOUNT_POINT" /etc/fstab; then
            log_warning "Entry for $MOUNT_POINT already exists in /etc/fstab"
        else
            echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab > /dev/null
            log_info "Entry added to /etc/fstab for persistent mounting"
        fi
    elif [ "$AUTO_FSTAB" = false ]; then
        read -p "Do you want to add this mount to /etc/fstab for persistent mounting? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            FSTAB_ENTRY="//$STORAGE_ACCOUNT.file.core.windows.net/$SHARE_NAME $MOUNT_POINT cifs nofail,vers=3.0,username=$STORAGE_ACCOUNT,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777,serverino,uid=$(id -u oracle),gid=$(id -g oracle) 0 0"
            
            # Check if entry already exists
            if grep -q "$MOUNT_POINT" /etc/fstab; then
                log_warning "Entry for $MOUNT_POINT already exists in /etc/fstab"
            else
                echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab > /dev/null
                log_info "Entry added to /etc/fstab"
            fi
        fi
    fi
else
    log_error "Failed to mount Azure file share"
    exit 1
fi

# Logout from Azure
az logout > /dev/null 2>&1 || true

log_info "Done!"
exit 0
```
### Create install-ora-weblogic.sh
```bash
#!/bin/bash

# Set variables
INSTALL_BASE="/usr/wls-install-recepies/install-bin"
JDK_TAR="jdk-17.0.12_linux-x64_bin.tar.gz"
WLS_JAR="fmw_14.1.1.0.0_wls_lite_generic.jar"
ORACLE_HOME="/oracle/middleware"
JAVA_HOME="/oracle/java"
INVENTORY_LOC="/oracle/oraInventory"
TEMP_DIR="/oracle/temp"
INV_PTR_FILE="/oracle/oraInst.loc"
RESPONSE_FILE="/oracle/wls_install.rsp"

# Function to print status messages
print_status() {
    echo "===================================================="
    echo "$1"
    echo "===================================================="
}

# Function to check if command succeeded
check_status() {
    if [ $? -eq 0 ]; then
        echo "✓ $1 completed successfully"
    else
        echo "✗ $1 failed"
        exit 1
    fi
}

print_status "Starting WebLogic Server Installation with JDK Setup"

# Check if source files exist
if [ ! -f "$INSTALL_BASE/$JDK_TAR" ]; then
    echo "Error: JDK file not found at $INSTALL_BASE/$JDK_TAR"
    exit 1
fi

if [ ! -f "$INSTALL_BASE/$WLS_JAR" ]; then
    echo "Error: WebLogic JAR file not found at $INSTALL_BASE/$WLS_JAR"
    exit 1
fi

print_status "Step 1: Creating Installation Directories"
mkdir -p $JAVA_HOME
mkdir -p $ORACLE_HOME
mkdir -p $INVENTORY_LOC
mkdir -p $TEMP_DIR
chmod 755 $JAVA_HOME $ORACLE_HOME $INVENTORY_LOC $TEMP_DIR
check_status "Directory creation"

print_status "Step 2: Extracting and Installing JDK 17"
cd $JAVA_HOME
tar -xzf $INSTALL_BASE/$JDK_TAR
check_status "JDK extraction"

# Find the extracted JDK directory (it should be jdk-17.0.12)
JDK_DIR=$(find $JAVA_HOME -maxdepth 1 -type d -name "jdk-17*" | head -1)
if [ -z "$JDK_DIR" ]; then
    echo "Error: Could not find extracted JDK directory"
    exit 1
fi

# Set JAVA_HOME to the extracted JDK directory
export JAVA_HOME=$JDK_DIR
export PATH=$JAVA_HOME/bin:$PATH

print_status "Step 3: Verifying Java Installation"
echo "Java Home: $JAVA_HOME"
echo "Java Version:"
java -version
check_status "Java verification"

print_status "Step 4: Creating WebLogic Response File and Inventory Location"
cat > $RESPONSE_FILE << EOF
[ENGINE]
Response File Version=1.0.0.0.0

[GENERIC]
ORACLE_HOME=$ORACLE_HOME
INSTALL_TYPE=WebLogic Server
DECLINE_SECURITY_UPDATES=true
SECURITY_UPDATES_VIA_MYORACLESUPPORT=false
AUTO_UPDATES=false
EOF

# Create inventory pointer file with absolute path
cat > $INV_PTR_FILE << EOF
inventory_loc=$INVENTORY_LOC
inst_group=$(id -gn)
EOF

echo "Created response file at: $RESPONSE_FILE"
echo "Created inventory pointer file at: $INV_PTR_FILE"
echo "Inventory pointer file contents:"
cat $INV_PTR_FILE
echo ""

check_status "Response file and inventory pointer creation"

print_status "Step 5: Running WebLogic Silent Installation"
echo "Using Java: $(which java)"
echo "Installing to: $ORACLE_HOME"
echo "Inventory Location: $INVENTORY_LOC"
echo "Inventory Pointer File: $INV_PTR_FILE"
echo "Temp Directory: $TEMP_DIR"
echo "Using installer: $INSTALL_BASE/$WLS_JAR"

# Check available space
echo "Checking disk space:"
df -h /oracle /tmp
echo ""

# Verify files exist before installation
echo "Verifying files before installation:"
echo "Response file ($RESPONSE_FILE): $(test -f $RESPONSE_FILE && echo 'YES' || echo 'NO')"
echo "Inventory pointer ($INV_PTR_FILE): $(test -f $INV_PTR_FILE && echo 'YES' || echo 'NO')"
echo "Installer ($INSTALL_BASE/$WLS_JAR): $(test -f $INSTALL_BASE/$WLS_JAR && echo 'YES' || echo 'NO')"
echo ""

# Set temporary directory environment variables
export TMPDIR=$TEMP_DIR
export TMP=$TEMP_DIR
export TEMP=$TEMP_DIR

java -Djava.io.tmpdir=$TEMP_DIR \
     -jar $INSTALL_BASE/$WLS_JAR \
     -silent \
     -responseFile $RESPONSE_FILE \
     -invPtrLoc $INV_PTR_FILE
check_status "WebLogic installation"

print_status "Step 6: Verifying WebLogic Installation"
if [ -f "$ORACLE_HOME/wlserver/server/bin/setWLSEnv.sh" ]; then
    echo "✓ WebLogic Server 14.1.1.0.0 installed successfully!"

    # Set WebLogic environment and display version
    cd $ORACLE_HOME/wlserver/server/bin
    source ./setWLSEnv.sh

    echo ""
    echo "WebLogic Server Version Information:"
    java weblogic.version

    echo ""
    echo "Installation Summary:"
    echo "- Java Home: $JAVA_HOME"
    echo "- Oracle Home: $ORACLE_HOME"
    echo "- WebLogic Server: $ORACLE_HOME/wlserver"
    echo "- Temp Directory: $TEMP_DIR"

    print_status "Creating Environment Setup Script"
    cat > /oracle/setenv.sh << EOF
#!/bin/bash
# WebLogic Server Environment Setup
export JAVA_HOME=$JAVA_HOME
export ORACLE_HOME=$ORACLE_HOME
export PATH=\$JAVA_HOME/bin:\$PATH
export WL_HOME=\$ORACLE_HOME/wlserver

# Source WebLogic environment
if [ -f "\$WL_HOME/server/bin/setWLSEnv.sh" ]; then
    source \$WL_HOME/server/bin/setWLSEnv.sh
fi

echo "WebLogic Server environment loaded"
echo "Java Home: \$JAVA_HOME"
echo "Oracle Home: \$ORACLE_HOME"
echo "WebLogic Home: \$WL_HOME"
EOF

    chmod +x /oracle/setenv.sh
    echo "✓ Environment setup script created at /oracle/setenv.sh"

    print_status "Cleaning Up Temporary Files"
    # Clean up the temporary installation files
    rm -rf $TEMP_DIR/orcl*
    rm -rf $TEMP_DIR/OraInstall*
    echo "✓ Temporary installation files cleaned up"

else
    echo "✗ WebLogic installation failed!"
    echo "Checking for installation logs..."
    find /tmp -name "*OraInstall*" -type d 2>/dev/null | head -5
    find $TEMP_DIR -name "*OraInstall*" -type d 2>/dev/null | head -5
    exit 1
fi

print_status "Installation Completed Successfully"
echo "To use WebLogic Server in future sessions, run:"
echo "source /oracle/setenv.sh"
```

### Create domain-create.sh
```bash
#!/usr/bin/env bash
# Setting environment variables for domain creation
domainName="DynamicDomain"
domainPath="/domains/$domainName"
templatePath="/oracle/middleware/wlserver/common/templates/wls/wls.jar"
JAVA_HOME="/oracle/java/jdk-17.0.12"

# Load creds and configuration
[[ -f "${CREDENTIAL_ENV:-/tmp/cred.env}" ]] || { echo "ERROR: .env not found"; exit 1; }
# shellcheck disable=SC1091
source "${CREDENTIAL_ENV}"

# Generate the WLST script for domain creation (OFFLINE MODE)
wlstScript="/tmp/create_domain.py"
cat <<EOF > $wlstScript
# Import WLST Library
import sys

# Define domain and environment variables
domainName = "$domainName"
domainPath = "$domainPath"
templatePath = "$templatePath"

try:
    print("Starting domain creation in OFFLINE mode...")
    
    # Load the base WebLogic template
    print("Loading template: " + templatePath)
    readTemplate(templatePath)
    
    # Configure Admin Server
    print("Configuring Admin Server...")
    cd('/Servers/AdminServer')
    set('ListenAddress', '')
    set('ListenPort', 7001)
    
    # Set domain security credentials - OFFLINE MODE
    print("Setting admin credentials...")
    cd('/')
    cd('Security/base_domain/User/weblogic')
    set('Password', '$WEBLOGIC_ADMIN_PASSWORD')
    
    # Set domain options
    setOption('OverwriteDomain', 'true')
    setOption('ServerStartMode', 'dev')
    
    # Write the new domain configuration to disk
    print("Writing domain to: " + domainPath)
    writeDomain(domainPath)
    closeTemplate()
    
    print("Domain creation completed successfully!")
    print("Domain location: " + domainPath)
    sys.exit(0)
    
except Exception, e:
    print("Error occurred during domain creation:")
    print(str(e))
    dumpStack()
    sys.exit(1)
EOF

# Source WebLogic Server environment
source /oracle/middleware/wlserver/server/bin/setWLSEnv.sh

# Execute WLST for domain creation using the generated WLST script
echo "Creating basic WebLogic domain..."
$JAVA_HOME/bin/java weblogic.WLST $wlstScript

if [ $? -ne 0 ]; then
    echo "ERROR: Domain creation failed!"
    exit 1
fi

echo "Basic domain created successfully!"
```

### Create create-dynamic-cluster.sh
```bash
#!/usr/bin/env bash
set -e  # Exit on any error

# Setting environment variables for domain configuration
domainName="DynamicDomain"
domainPath="/domains/$domainName"
JAVA_HOME="/oracle/java/jdk-17.0.12"

# Cluster 1 configuration
cluster1Name="jupiter-cluster"
server1NamePrefix="jupiter-server-"
cluster1Size=4
machine1MatchExpression="dyn-machine1*"

# Cluster 2 configuration
cluster2Name="mars-cluster"
server2NamePrefix="mars-server-"
cluster2Size=4
machine2MatchExpression="dyn-machine2*"

# Determine credential file location
CREDENTIAL_ENV="${CREDENTIAL_ENV:-/tmp/.env}"

# Check if credential file exists
if [[ ! -f "$CREDENTIAL_ENV" ]]; then
    echo "ERROR: Credential file not found at: $CREDENTIAL_ENV"
    echo "Checking common locations..."
    
    # Try alternative locations
    if [[ -f "/tmp/.env" ]]; then
        CREDENTIAL_ENV="/tmp/.env"
        echo "Found credentials at: /tmp/.env"
    elif [[ -f "/tmp/cred.env" ]]; then
        CREDENTIAL_ENV="/tmp/cred.env"
        echo "Found credentials at: /tmp/cred.env"
    else
        echo "ERROR: No credential file found!"
        exit 1
    fi
fi

# Load credentials
echo "Loading credentials from: $CREDENTIAL_ENV"
# shellcheck disable=SC1090
source "$CREDENTIAL_ENV"

# Validate required variables
if [[ -z "$WEBLOGIC_ADMIN_PASSWORD" ]]; then
    echo "ERROR: WEBLOGIC_ADMIN_PASSWORD not set in $CREDENTIAL_ENV"
    exit 1
fi

echo "Credentials loaded successfully"

# Generate the WLST script for dynamic cluster creation (OFFLINE MODE)
wlstScript="/tmp/create_dynamic_cluster.py"
cat <<'EOF' > $wlstScript
#
# This example demonstrates the WLST commands needed to create dynamic clusters
# in OFFLINE mode. The dynamic clusters use server templates.
# OFFLINE mode uses create()/set() instead of cmo.createX()/setX() methods.
#
import sys

# Define domain and cluster variables
domainPath = "$DOMAIN_PATH"

cluster1Name = "$CLUSTER1_NAME"
server1NamePrefix = "$SERVER1_NAME_PREFIX"
template1Name = cluster1Name + "-server-template"
cluster1Size = $CLUSTER1_SIZE
machine1MatchExpression = "$MACHINE1_MATCH_EXPRESSION"

cluster2Name = "$CLUSTER2_NAME"
server2NamePrefix = "$SERVER2_NAME_PREFIX"
template2Name = cluster2Name + "-server-template"
cluster2Size = $CLUSTER2_SIZE
machine2MatchExpression = "$MACHINE2_MATCH_EXPRESSION"

try:
    print("Reading existing domain in OFFLINE mode...")
    readDomain(domainPath)
    
    #
    # Create the server template for the dynamic servers and set the attributes for
    # the dynamic servers. Setting the cluster is not required.
    #
    print("Creating server template: " + template1Name)
    cd('/')
    create(template1Name, 'ServerTemplate')
    cd('/ServerTemplates/' + template1Name)
    set('AcceptBacklog', 2000)
    set('AutoRestart', True)
    set('RestartMax', 10)
    set('StartupTimeout', 600)
    set('ListenPort', 8001)
    
    #
    # Create the dynamic cluster, set the number of dynamic servers, and designate the server template.
    #
    print("Creating dynamic cluster: " + cluster1Name)
    cd('/')
    create(cluster1Name, 'Cluster')
    cd('/Clusters/' + cluster1Name)
    
    # Create DynamicServers configuration
    create(cluster1Name + '-DynamicServers', 'DynamicServers')
    cd('/Clusters/' + cluster1Name + '/DynamicServers/' + cluster1Name + '-DynamicServers')
    set('DynamicClusterSize', cluster1Size)
    set('ServerTemplate', template1Name)
    
    #
    # Dynamic server names will be jupiter-server-1, jupiter-server-2, jupiter-server-3,
    # jupiter-server-4.
    #
    set('ServerNamePrefix', server1NamePrefix)
    
    #
    # Listen ports and machines assignments will be calculated. Using a round-robin
    # algorithm, servers will be assigned to machines with names that start with
    # dyn-machine1.
    #
    set('CalculatedListenPorts', True)
    set('CalculatedMachineNames', True)
    set('MachineNameMatchExpression', machine1MatchExpression)
    
    #
    # Create the server template for the dynamic servers and set the attributes for
    # the dynamic servers. Setting the cluster is not required.
    #
    print("Creating server template: " + template2Name)
    cd('/')
    create(template2Name, 'ServerTemplate')
    cd('/ServerTemplates/' + template2Name)
    set('AcceptBacklog', 2000)
    set('AutoRestart', True)
    set('RestartMax', 10)
    set('StartupTimeout', 600)
    set('ListenPort', 8001)
    
    #
    # Create the dynamic cluster, set the number of dynamic servers, and designate the server template.
    #
    print("Creating dynamic cluster: " + cluster2Name)
    cd('/')
    create(cluster2Name, 'Cluster')
    cd('/Clusters/' + cluster2Name)
    
    # Create DynamicServers configuration
    create(cluster2Name + '-DynamicServers', 'DynamicServers')
    cd('/Clusters/' + cluster2Name + '/DynamicServers/' + cluster2Name + '-DynamicServers')
    set('DynamicClusterSize', cluster2Size)
    set('ServerTemplate', template2Name)
    
    #
    # Dynamic server names will be mars-server-1, mars-server-2, mars-server-3,
    # mars-server-4.
    #
    set('ServerNamePrefix', server2NamePrefix)
    
    #
    # Listen ports and machines assignments will be calculated. Using a round-robin
    # algorithm, servers will be assigned to machines with names that start with
    # dyn-machine2.
    #
    set('CalculatedListenPorts', True)
    set('CalculatedMachineNames', True)
    set('MachineNameMatchExpression', machine2MatchExpression)
    
    #
    # Update and save the domain configuration
    #
    print("Updating domain with dynamic cluster configuration...")
    updateDomain()
    closeDomain()
    
    print("")
    print("=" * 60)
    print("Dynamic Clusters created successfully!")
    print("=" * 60)
    print("Cluster 1: " + cluster1Name)
    print("  - Server Template: " + template1Name)
    print("  - Cluster Size: " + str(cluster1Size))
    print("  - Server Name Prefix: " + server1NamePrefix)
    print("  - Machine Match: " + machine1MatchExpression)
    print("")
    print("Cluster 2: " + cluster2Name)
    print("  - Server Template: " + template2Name)
    print("  - Cluster Size: " + str(cluster2Size))
    print("  - Server Name Prefix: " + server2NamePrefix)
    print("  - Machine Match: " + machine2MatchExpression)
    print("=" * 60)
    
    sys.exit(0)
    
except Exception, e:
    print("Error occurred during dynamic cluster creation:")
    print(str(e))
    dumpStack()
    try:
        closeDomain()
    except:
        pass
    sys.exit(1)
EOF

# Substitute variables into the WLST script
sed -i "s|\$DOMAIN_PATH|$domainPath|g" $wlstScript
sed -i "s|\$CLUSTER1_NAME|$cluster1Name|g" $wlstScript
sed -i "s|\$SERVER1_NAME_PREFIX|$server1NamePrefix|g" $wlstScript
sed -i "s|\$CLUSTER1_SIZE|$cluster1Size|g" $wlstScript
sed -i "s|\$MACHINE1_MATCH_EXPRESSION|$machine1MatchExpression|g" $wlstScript
sed -i "s|\$CLUSTER2_NAME|$cluster2Name|g" $wlstScript
sed -i "s|\$SERVER2_NAME_PREFIX|$server2NamePrefix|g" $wlstScript
sed -i "s|\$CLUSTER2_SIZE|$cluster2Size|g" $wlstScript
sed -i "s|\$MACHINE2_MATCH_EXPRESSION|$machine2MatchExpression|g" $wlstScript

# Source WebLogic Server environment
echo "Setting up WebLogic environment..."
if [[ ! -f "/oracle/middleware/wlserver/server/bin/setWLSEnv.sh" ]]; then
    echo "ERROR: setWLSEnv.sh not found"
    exit 1
fi

source /oracle/middleware/wlserver/server/bin/setWLSEnv.sh

# Check if domain exists
if [[ ! -d "$domainPath" ]]; then
    echo "ERROR: Domain not found at: $domainPath"
    echo "Please run domain-create.sh first to create the base domain"
    exit 1
fi

# Execute WLST for dynamic cluster creation in OFFLINE mode
echo "Adding Dynamic Clusters to existing domain (OFFLINE mode)..."
$JAVA_HOME/bin/java weblogic.WLST $wlstScript

if [ $? -ne 0 ]; then
    echo "ERROR: Dynamic Cluster creation failed!"
    exit 1
fi

echo ""
echo "=========================================="
echo "Dynamic Clusters setup completed successfully!"
echo "=========================================="
echo "Domain Path: $domainPath"
echo "Clusters: $cluster1Name, $cluster2Name"
echo ""
echo "The clusters will be visible after starting the Admin Server"
echo "=========================================="
```

### Create enable-wls-startup.sh
```bash
#!/bin/bash

# Disable SELinux enforcement (immediate and permanent)
echo "Setting SELinux to permissive mode and disabling permanently..."
sudo setenforce 0

# Fix: Use the correct SELinux config file
sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

# Also update the legacy location if it exists (for compatibility)
if [ -f /etc/sysconfig/selinux ]; then
    sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/sysconfig/selinux
fi

# Verify the change
echo "Current SELinux config:"
grep "^SELINUX=" /etc/selinux/config

# Disable the systemd firewalld service
echo "Disabling systemd firewall (firewalld)..."
sudo systemctl stop firewalld
sudo systemctl disable firewalld

# Create the WebLogic Admin service definition
SERVICE_FILE="/etc/systemd/system/weblogic-admin.service"
echo "Creating WebLogic Admin Service: $SERVICE_FILE"
sudo tee $SERVICE_FILE > /dev/null <<EOL
[Unit]
Description=Weblogic Admin Server
After=network.target

[Service]
Type=simple
User=oracle
Environment="JAVA_HOME=/oracle/java/jdk-17.0.12"
Environment="DOMAIN_HOME=/oracle/domains/DynamicDomain"
WorkingDirectory=/domains/DynamicDomain
ExecStart=/domains/DynamicDomain/bin/startWebLogic.sh
Restart=on-failure
RestartSec=30
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOL

# Set file permissions
echo "Setting permissions for the service file..."
sudo chmod 644 $SERVICE_FILE

# Reload and enable the new service
echo "Reloading systemd, enabling and starting WebLogic Admin service..."
sudo systemctl daemon-reload
sudo systemctl enable weblogic-admin
sudo systemctl start weblogic-admin

# Check the status
echo "Checking the status of Weblogic Admin service..."
sudo systemctl status weblogic-admin

echo ""
echo "=== IMPORTANT ==="
echo "SELinux has been disabled but requires a REBOOT to take full effect."
echo "After reboot, verify with: getenforce (should show 'Disabled')"
echo "=================="
```
