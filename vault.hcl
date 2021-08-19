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