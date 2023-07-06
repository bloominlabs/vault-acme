export VAULT_ADDR='http://127.0.0.1:8200' 
export VAULT_TOKEN=root

vault secrets enable -path=acme -plugin-name=acme plugin
vault write acme/accounts/letsencrypt-test contact=kevin@bloominlabs.com provider=cloudflare provider_configuration=CLOUDFLARE_DNS_API_TOKEN=<vault read cloudflare/creds/edit-dns> registration_uri=https://acme-v02.api.letsencrypt.org/acme/acct/594018726 server_url=https://acme-staging-v02.api.letsencrypt.org/directory terms_of_service_agreed=true
vault write acme/roles/serverd-test account=letsencrypt-test allow_subdomains=true allowed_domains=stratos.game
vault write acme/certs/serverd-test common_name=test-valheim.stratos.game
