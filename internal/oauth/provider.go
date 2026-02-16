package oauth

import (
	"fmt"
	"log"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/models"
)

type Provider interface {
	GetAuthCodeURL(state string) string
	ExchangeUserInfo(code string) (models.User, error)
}

func CreateProviders(serviceDomain string, confs map[string]config.ProviderConfig) map[string]Provider {
	providers := make(map[string]Provider)
	for name, options := range confs {
		provider, err := createProvider(serviceDomain, name, options)
		if err != nil {
			log.Printf("%s\nSkipping provider: %s\n", err, name)
			continue
		}
		providers[name] = provider
	}
	return providers
}

func createProvider(serviceDomain, providerName string, conf config.ProviderConfig) (Provider, error) {
	switch providerName {
	case "google":
		return NewGoogleProviderFromConf(serviceDomain, conf)
	default:
		return nil, fmt.Errorf("unknown provider: %s\n", providerName)
	}
}
