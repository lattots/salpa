package handler

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/oauth"
	"github.com/lattots/salpa/internal/token"
)

type Handler struct {
	providers     map[string]oauth.Provider
	token         *token.Manager
	appDomain     string // This is the domain name of the client application
	serviceDomain string // This is the domain name of the auth service
}

func CreateHandlerFromConf(conf config.SystemConfiguration, tokenManager *token.Manager) (*Handler, error) {
	if len(conf.Providers) == 0 {
		return nil, errors.New("error no auth providers")
	}

	providers := oauth.CreateProviders(conf.Service.ServiceDomain, conf.Providers)
	if len(slices.Collect(maps.Keys(providers))) == 0 {
		return nil, fmt.Errorf("no providers set in conf. Please set providers in configuration file\n")
	}

	h := &Handler{
		providers:     providers,
		token:         tokenManager,
		appDomain:     conf.Service.AppDomain,
		serviceDomain: conf.Service.ServiceDomain,
	}

	return h, nil
}
