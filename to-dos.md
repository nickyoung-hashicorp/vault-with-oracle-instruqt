### Used Oracle's repo to build image for Oracle Database 18c (18.4.0) Express Edition (XE)
 - https://github.com/oracle/docker-images/blob/main/OracleDatabase/SingleInstance/README.md

### Downloaded database file from Oracle
wget https://download.oracle.com/otn-pub/otn_software/db-express/oracle-database-xe-18c-1.0-1.x86_64.rpm

### Run container
docker run --name oracledb \
    -d --restart unless-stopped \
    -p 1521:1521 \
    -p 5500:5500 \
    -e ORACLE_PWD=mysecurepassword \
    -e ORACLE_CHARACTERSET=AL32UTF8 \
    oracle/database:18.4.0-xe

---Saved Snapshot: build-vault-oracle-base-docker---

### Download Oracle Software and Vault's Oracle Plugin
wget https://download.oracle.com/otn_software/linux/instantclient/199000/instantclient-basic-linux.x64-19.9.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/199000/instantclient-sqlplus-linux.x64-19.9.0.0.0dbru.zip
wget https://releases.hashicorp.com/vault-plugin-database-oracle/0.2.1/vault-plugin-database-oracle_0.2.1_linux_amd64.zip

### Environment Variables
cat << EOF > ~/.bashrc
#!/bin/bash
export VAULT_SKIP_VERIFY=true
export VAULT_ADDR=http://127.0.0.1:8200
export ORACLE_PATH_PREFIX="oracle_vault"
export VAULT_PLUGIN_DIRECTORY="/data/vault/plugins"
export PATH="$PATH:/opt/oracle/instantclient_19_9"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/opt/oracle/instantclient_19_9"
EOF
source ~/.bashrc

### Oracle Client Install
sudo mkdir /opt/oracle
sudo unzip -d /opt/oracle instantclient-basic-linux.x64-19.9.0.0.0dbru.zip
sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-19.9.0.0.0dbru.zip
sudo sh -c "echo /opt/oracle/instantclient_19_9 > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig

### Create Vault Setup Script
vim setup.sh
------------
#!/usr/bin/env bash

# Setup vault enterprise as server
set -e

# USER VARS
NODE_NAME="${1:-$(hostname -s)}"
VAULT_VERSION="1.7.3"
VAULT_DIR=/usr/local/bin
VAULT_CONFIG_DIR=/etc/vault.d
VAULT_DATA_DIR=/opt/vault

# CALCULATED VARS
VAULT_PATH=${VAULT_DIR}/vault
VAULT_ZIP="vault_${VAULT_VERSION}_linux_amd64.zip"
VAULT_URL="https://releases.hashicorp.com/vault/${VAULT_VERSION}/${VAULT_ZIP}"


# CHECK DEPENDANCIES AND SET NET RETRIEVAL TOOL
if ! unzip -h 2&> /dev/null; then
  echo "aborting - unzip not installed and required"
  exit 1
fi
if curl -h 2&> /dev/null; then
  nettool="curl"
elif wget -h 2&> /dev/null; then
  nettool="wget"
else
  echo "aborting - neither wget nor curl installed and required"
  exit 1
fi

set +e
# try to get private IP
pri_ip=$(hostname -I 2> /dev/null | awk '{print $1}')
set -e

# download and extract binary
echo "Downloading and installing vault ${VAULT_VERSION}"
case "${nettool}" in
  wget)
    wget --no-check-certificate "${VAULT_URL}" --output-document="${VAULT_ZIP}"
    ;;
  curl)
    [ 200 -ne $(curl --write-out %{http_code} --silent --output ${VAULT_ZIP} ${VAULT_URL}) ] && exit 1
    ;;
esac

unzip "${VAULT_ZIP}"
sudo mv vault "$VAULT_DIR"
sudo chmod 0755 "${VAULT_PATH}"
sudo chown root:root "${VAULT_PATH}"


echo "Version Installed: $(vault --version)"
vault -autocomplete-install
complete -C "${VAULT_PATH}" vault
sudo setcap cap_ipc_lock=+ep "${VAULT_PATH}"


echo "Creating Vault user and directories"
sudo mkdir --parents "${VAULT_CONFIG_DIR}"
sudo useradd --system --home "${VAULT_CONFIG_DIR}" --shell /bin/false vault
sudo mkdir --parents "${VAULT_DATA_DIR}"
sudo chown --recursive vault:vault "${VAULT_DATA_DIR}"

echo "Creating directory for Oracle DB plugin"
sudo mkdir -pm 0755 /data/vault/plugins
sudo chown -R vault:vault /data/vault/plugins


echo "Creating vault config for ${VAULT_VERSION}"
sudo tee "${VAULT_CONFIG_DIR}/vault.hcl" > /dev/null <<VAULTCONFIG
ui = true
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
plugin_directory="/data/vault/plugins"

listener "tcp" {
  address          = "127.0.0.1:8200"
  cluster_address  = "127.0.0.1:8201"
  tls_disable      = true
}

storage "raft" {
  path    = "/opt/vault"
  node_id = "vault-1"
}
VAULTCONFIG

sudo chown --recursive vault:vault "${VAULT_CONFIG_DIR}"
sudo chmod 640 "${VAULT_CONFIG_DIR}/vault.hcl"


echo "Creating vault systemd service"
sudo tee /etc/systemd/system/vault.service > /dev/null <<SYSDSERVICE
[Unit]
Description="HashiCorp Vault - A tool for managing secrets"
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=VAULTBINDIR/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitIntervalSec=60
StartLimitBurst=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSDSERVICE

sudo sed -i "s|VAULTBINDIR|$VAULT_DIR|g" /etc/systemd/system/vault.service
------------

chmod +x setup.sh
./setup.sh

### Unzip and setcap for plugin
sudo unzip -d /data/vault/plugins vault-plugin-database-oracle_0.2.1_linux_amd64.zip
sudo setcap cap_ipc_lock=+ep /data/vault/plugins/vault-plugin-database-oracle


### Enable and Start Vault Service
vim start.sh
------------
echo "Starting Vault systemd service"
sudo systemctl enable vault
sudo systemctl start vault

sleep 5
echo "Initializing Vault with vault operator init..."
vault operator init -key-shares=1 -key-threshold=1 -format=json > vault_init.json
sleep 5
echo "Moving vault_init.json to /etc/vault.d directory"
sudo mv vault_init.json /etc/vault.d/vault_init.json
echo "Unsealing Vault..."
vault operator unseal $(jq -r .unseal_keys_b64[0] < /etc/vault.d/vault_init.json)
sleep 10
echo "Logging into Vault with the root token..."
vault login $(jq -r .root_token < /etc/vault.d/vault_init.json)
------------

chmod +x start.sh
./start.sh

### Enable the database secret engine
vault secrets enable -path=oracle_vault database

### Register the Vault plugin
export ORACLE_PLUGIN_SHA256SUM=$(sha256sum /data/vault/plugins/vault-plugin-database-oracle | awk '{print $1}')

echo ${ORACLE_PLUGIN_SHA256SUM}

vault write \
  sys/plugins/catalog/database/oracle-database-plugin \
  sha256="${ORACLE_PLUGIN_SHA256SUM}" \
  command=vault-plugin-database-oracle

### Configure Oracle plugin using 2 allowed role IDs
vault write \
  oracle_vault/config/wsoracledatabase \
  plugin_name=oracle-database-plugin \
  connection_url="{{username}}/{{password}}@//localhost:1521/XE?as=sysdba" \
  allowed_roles="1hTTL","3mTTL" \
  username="sys" \
  password="mysecurepassword"

vault write \
  oracle_vault/roles/1hTTL \
  db_name=wsoracledatabase \
  creation_statements="alter session set \"_ORACLE_SCRIPT\"=true;  CREATE USER {{name}} IDENTIFIED BY {{password}}; GRANT CONNECT TO {{name}}; GRANT CREATE SESSION TO {{name}};" \
  default_ttl="1h" \
  max_ttl="8h"

vault write \
  oracle_vault/roles/3mTTL \
  db_name=wsoracledatabase \
  creation_statements="alter session set \"_ORACLE_SCRIPT\"=true;  CREATE USER {{name}} IDENTIFIED BY {{password}}; GRANT CONNECT TO {{name}}; GRANT CREATE SESSION TO {{name}};" \
  default_ttl="3m" \
  max_ttl="6m"

### Generate Credentials
vault read oracle_vault/creds/3mTTL
vault read oracle_vault/creds/1hTTL

### View Credentials
read ORACLE_DYNAMIC_USER ORACLE_DYNAMIC_PASSWORD ORACLE_DYNAMIC_LEASE_ID < <(echo $(vault read -format=json oracle_vault/creds/1hTTL | jq -r '.data.username, .data.password, .lease_id') )

echo "Vault-Generated User : ${ORACLE_DYNAMIC_USER}" && echo "Vault-Generated Password : ${ORACLE_DYNAMIC_PASSWORD}" && echo "Lease ID : ${ORACLE_DYNAMIC_LEASE_ID}"

### Login to Oracle
sqlplus ${ORACLE_DYNAMIC_USER}/${ORACLE_DYNAMIC_PASSWORD}@//localhost:1521/XE?as=sysdba

### Test SQL Commands
select username from all_users order by created;

### Exit
exit