package acme

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/exec"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func getCertFromACMEProvider(ctx context.Context, logger log.Logger, req *logical.Request, a *account, names []string) (*certificate.Resource, error) {
	client, err := a.getClient()
	if err != nil {
		return nil, err
	}

	err = setupChallengeProviders(ctx, logger, client, a, req)
	if err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	}

	return client.Certificate.Obtain(request)
}

func getDNSProvider(ctx context.Context, provider string, providerConfiguration map[string]string) (challenge.Provider, error) {
	var cp challenge.Provider
	switch provider {
	case "exec":
		config := exec.NewDefaultConfig()
		values, err := env.Get(exec.EnvPath)
		if err != nil {
			return cp, fmt.Errorf("exec: %w", err)
		}

		config.Program = values[exec.EnvPath]
		config.Mode = os.Getenv(exec.EnvMode)

		if providerConfiguration[exec.EnvMode] != "" {
			config.Mode = providerConfiguration[exec.EnvMode]
		}
		if providerConfiguration[exec.EnvPath] != "" {
			config.Program = providerConfiguration[exec.EnvPath]
		}
		if providerConfiguration[exec.EnvPropagationTimeout] != "" {
			dur, err := time.ParseDuration(providerConfiguration[exec.EnvPropagationTimeout])
			if err != nil {
				return cp, fmt.Errorf("failed to parse '%s': %w", exec.EnvPropagationTimeout, err)
			}
			config.PropagationTimeout = dur
		}
		if providerConfiguration[exec.EnvPollingInterval] != "" {
			dur, err := time.ParseDuration(providerConfiguration[exec.EnvPollingInterval])
			if err != nil {
				return cp, fmt.Errorf("failed to parse '%s': %w", exec.EnvPollingInterval, err)
			}
			config.PollingInterval = dur
		}
		if providerConfiguration[exec.EnvSequenceInterval] != "" {
			dur, err := time.ParseDuration(providerConfiguration[exec.EnvSequenceInterval])
			if err != nil {
				return cp, fmt.Errorf("failed to parse '%s': %w", exec.EnvSequenceInterval, err)
			}
			config.SequenceInterval = dur
		}

		return exec.NewDNSProviderConfig(config)
	case "cloudflare":
		config := cloudflare.NewDefaultConfig()
		if providerConfiguration["CLOUDFLARE_EMAIL"] != "" {
			config.AuthEmail = providerConfiguration["CLOUDFLARE_EMAIL"]
		}
		if providerConfiguration["CF_API_EMAIL"] != "" {
			config.AuthEmail = providerConfiguration["CF_API_EMAIL"]
		}
		if providerConfiguration["CLOUDFLARE_API_KEY"] != "" {
			config.AuthKey = providerConfiguration["CLOUDFLARE_API_KEY"]
		}
		if providerConfiguration["CF_API_KEY"] != "" {
			config.AuthKey = providerConfiguration["CF_API_KEY"]
		}
		if providerConfiguration["CLOUDFLARE_DNS_API_TOKEN"] != "" {
			config.AuthToken = providerConfiguration["CLOUDFLARE_DNS_API_TOKEN"]
		}
		if providerConfiguration["CF_DNS_API_TOKEN"] != "" {
			config.AuthToken = providerConfiguration["CF_DNS_API_TOKEN"]
		}
		if providerConfiguration["CLOUDFLARE_ZONE_API_TOKEN"] != "" {
			config.ZoneToken = providerConfiguration["CLOUDFLARE_ZONE_API_TOKEN"]
		}
		if providerConfiguration["CF_ZONE_API_TOKEN"] != "" {
			config.ZoneToken = providerConfiguration["CF_ZONE_API_TOKEN"]
		}
		if providerConfiguration["CLOUDFLARE_HTTP_TIMEOUT"] != "" {
			dur, err := time.ParseDuration(providerConfiguration["CLOUDFLARE_HTTP_TIMEOUT"])
			if err != nil {
				return cp, fmt.Errorf("failed to parse 'CLOUDFLARE_HTTP_TIMEOUT': %w", err)
			}
			config.HTTPClient.Timeout = dur
		}
		if providerConfiguration["CLOUDFLARE_POLLING_INTERVAL"] != "" {
			dur, err := time.ParseDuration(providerConfiguration["CLOUDFLARE_POLLING_INTERVAL"])
			if err != nil {
				return cp, fmt.Errorf("failed to parse 'CLOUDFLARE_POLLING_INTERVAL': %w", err)
			}
			config.PollingInterval = dur
		}
		if providerConfiguration["CLOUDFLARE_PROPAGATION_TIMEOUT"] != "" {
			dur, err := time.ParseDuration(providerConfiguration["CLOUDFLARE_PROPAGATION_TIMEOUT"])
			if err != nil {
				return cp, fmt.Errorf("failed to parse 'CLOUDFLARE_PROPAGATION_TIMEOUT': %w", err)
			}
			config.PropagationTimeout = dur
		}
		if providerConfiguration["CLOUDFLARE_TTL"] != "" {
			ttl, err := strconv.Atoi(providerConfiguration["CLOUDFLARE_TTL"])
			if err != nil {
				return cp, fmt.Errorf("failed to parse 'CLOUDFLARE_TTL': %w", err)
			}
			config.TTL = ttl
		}

		return cloudflare.NewDNSProviderConfig(config)
	default:
		return cp, fmt.Errorf("provider %s is not supported", provider)
	}
}

func setupChallengeProviders(ctx context.Context, logger log.Logger, client *lego.Client, a *account, req *logical.Request) error {
	// DNS-01
	if a.Provider != "" {
		provider, err := getDNSProvider(ctx, a.Provider, a.ProviderConfiguration)
		if err != nil {
			return err
		}
		err = client.Challenge.SetDNS01Provider(
			provider,
			dns01.CondOption(len(a.DNSResolvers) > 0, dns01.AddRecursiveNameservers(a.DNSResolvers)),
			dns01.CondOption(a.IgnoreDNSPropagation, dns01.DisableCompletePropagationRequirement()),
		)
		if err != nil {
			return err
		}
	}

	// HTTP-01
	if a.EnableHTTP01 {
		provider := newVaultHTTP01Provider(ctx, logger, req)
		err := client.Challenge.SetHTTP01Provider(provider)
		if err != nil {
			return err
		}
	}

	// TLS-ALPN-01
	if a.EnableTLSALPN01 {
		provider := newVaultTLSALPN01Provider(ctx, logger, req)
		err := client.Challenge.SetTLSALPN01Provider(provider)
		if err != nil {
			return err
		}
	}

	return nil
}
