package api

import (
	"github.com/infrahq/infra/uid"
)

// ProviderAPICredentials contain sensitive fields, it should not be sent on a response
type ProviderAPICredentials struct {
	PrivateKey  PEM    `json:"privateKey" example:"-----BEGIN PRIVATE KEY-----\nMIIDNTCCAh2gAwIBAgIRALRetnpcTo9O3V2fAK3ix+c\n-----END PRIVATE KEY-----\n"`
	ClientEmail string `json:"clientEmail"`
	DomainAdmin string `json:"domainAdmin"`
}

type Provider struct {
	ID       uid.ID   `json:"id"`
	Name     string   `json:"name" example:"okta"`
	Created  Time     `json:"created"`
	Updated  Time     `json:"updated"`
	URL      string   `json:"url" validate:"required" example:"infrahq.okta.com"`
	ClientID string   `json:"clientID" validate:"required" example:"0oapn0qwiQPiMIyR35d6"`
	Kind     string   `json:"kind" example:"oidc"`
	AuthURL  string   `json:"authURL" example:"https://example.com/oauth2/v1/authorize"`
	Scopes   []string `json:"scopes" example:"['openid', 'email']"`
}

type CreateProviderRequest struct {
	Name         string                 `json:"name" validate:"required" example:"okta"`
	URL          string                 `json:"url" validate:"required" example:"infrahq.okta.com"`
	ClientID     string                 `json:"clientID" validate:"required" example:"0oapn0qwiQPiMIyR35d6"`
	ClientSecret string                 `json:"clientSecret" validate:"required" example:"jmda5eG93ax3jMDxTGrbHd_TBGT6kgNZtrCugLbU"`
	Kind         string                 `json:"kind" validate:"omitempty,oneof=oidc okta azure google" example:"oidc"`
	API          ProviderAPICredentials `json:"api"`
}

type UpdateProviderRequest struct {
	ID           uid.ID                 `uri:"id" json:"-" validate:"required"`
	Name         string                 `json:"name" validate:"required" example:"okta"`
	URL          string                 `json:"url" validate:"required" example:"infrahq.okta.com"`
	ClientID     string                 `json:"clientID" validate:"required" example:"0oapn0qwiQPiMIyR35d6"`
	ClientSecret string                 `json:"clientSecret" validate:"required" example:"jmda5eG93ax3jMDxTGrbHd_TBGT6kgNZtrCugLbU"`
	Kind         string                 `json:"kind" validate:"omitempty,oneof=oidc okta azure google" example:"oidc"`
	API          ProviderAPICredentials `json:"api,omitempty"`
}

type ListProvidersRequest struct {
	Name string `form:"name" example:"okta"`
	PaginationRequest
}
