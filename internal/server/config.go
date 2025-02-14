package server

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/infrahq/secrets"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/infrahq/infra/internal"
	"github.com/infrahq/infra/internal/logging"
	"github.com/infrahq/infra/internal/server/data"
	"github.com/infrahq/infra/internal/server/models"
	"github.com/infrahq/infra/internal/server/providers"
	"github.com/infrahq/infra/uid"
)

type Provider struct {
	Name         string `validate:"required"`
	URL          string `validate:"required"`
	ClientID     string `validate:"required"`
	ClientSecret string `validate:"required"`
	Kind         string
	AuthURL      string
	Scopes       []string
}

type Grant struct {
	User     string `validate:"excluded_with=Group,excluded_with=Machine"`
	Group    string `validate:"excluded_with=User,excluded_with=Machine"`
	Machine  string `validate:"excluded_with=User,excluded_with=Group"` // deprecated
	Resource string `validate:"required"`
	Role     string
}

type User struct {
	Name      string `validate:"excluded_with=Email"`
	AccessKey string
	Password  string

	Email string `validate:"excluded_with=Name"` // deprecated
}

type Config struct {
	Providers []Provider `validate:"dive"`
	Grants    []Grant    `validate:"dive"`
	Users     []User     `validate:"dive"`
}

type KeyProvider struct {
	Kind   string      `validate:"required"`
	Config interface{} // contains secret-provider-specific config
}

type nativeKeyProviderConfig struct {
	SecretProvider string
}

type AWSConfig struct {
	Endpoint        string `validate:"required"`
	Region          string `validate:"required"`
	AccessKeyID     string `validate:"required"`
	SecretAccessKey string `validate:"required"`
}

type AWSKMSConfig struct {
	AWSConfig

	EncryptionAlgorithm string
	// aws tags?
}

type AWSSecretsManagerConfig struct {
	AWSConfig
}

type AWSSSMConfig struct {
	AWSConfig
	KeyID string `validate:"required"` // KMS key to use for decryption
}

type GenericConfig struct {
	Base64           bool
	Base64URLEncoded bool
	Base64Raw        bool
}

type FileConfig struct {
	GenericConfig
	Path string `validate:"required"`
}

type KubernetesConfig struct {
	Namespace string
}

type VaultConfig struct {
	TransitMount string // mounting point. defaults to /transit
	SecretMount  string // mounting point. defaults to /secret
	Token        string `validate:"required"`
	Namespace    string
	Address      string `validate:"required"`
}

func importKeyProviders(
	cfg []KeyProvider,
	storage map[string]secrets.SecretStorage,
	keys map[string]secrets.SymmetricKeyProvider,
) error {
	var err error

	// default to file-based native secret provider
	keys["native"] = secrets.NewNativeKeyProvider(storage["file"])

	for _, keyConfig := range cfg {
		switch keyConfig.Kind {
		case "native":
			cfg, ok := keyConfig.Config.(nativeKeyProviderConfig)
			if !ok {
				return fmt.Errorf("expected key config to be nativeKeyProviderConfig, but was %t", keyConfig.Config)
			}

			storageProvider, found := storage[cfg.SecretProvider]
			if !found {
				return fmt.Errorf("secret storage name %q not found", cfg.SecretProvider)
			}

			sp := secrets.NewNativeKeyProvider(storageProvider)
			keys[keyConfig.Kind] = sp
		case "awskms":
			cfg, ok := keyConfig.Config.(AWSKMSConfig)
			if !ok {
				return fmt.Errorf("expected key config to be AWSKMSConfig, but was %t", keyConfig.Config)
			}

			cfg.AccessKeyID, err = secrets.GetSecret(cfg.AccessKeyID, storage)
			if err != nil {
				return fmt.Errorf("getting secret for awskms accessKeyID: %w", err)
			}

			cfg.SecretAccessKey, err = secrets.GetSecret(cfg.SecretAccessKey, storage)
			if err != nil {
				return fmt.Errorf("getting secret for awskms secretAccessKey: %w", err)
			}

			kmsCfg := secrets.NewAWSKMSConfig()
			kmsCfg.AWSConfig.AccessKeyID = cfg.AccessKeyID
			kmsCfg.AWSConfig.Endpoint = cfg.Endpoint
			kmsCfg.AWSConfig.Region = cfg.Region
			kmsCfg.AWSConfig.SecretAccessKey = cfg.SecretAccessKey
			if len(cfg.EncryptionAlgorithm) > 0 {
				kmsCfg.EncryptionAlgorithm = cfg.EncryptionAlgorithm
			}

			sp, err := secrets.NewAWSKMSSecretProviderFromConfig(kmsCfg)
			if err != nil {
				return err
			}

			keys[keyConfig.Kind] = sp
		case "vault":
			cfg, ok := keyConfig.Config.(VaultConfig)
			if !ok {
				return fmt.Errorf("expected key config to be VaultConfig, but was %t", keyConfig.Config)
			}

			cfg.Token, err = secrets.GetSecret(cfg.Token, storage)
			if err != nil {
				return err
			}

			vcfg := secrets.NewVaultConfig()
			if len(cfg.TransitMount) > 0 {
				vcfg.TransitMount = cfg.TransitMount
			}
			if len(cfg.SecretMount) > 0 {
				vcfg.SecretMount = cfg.SecretMount
			}
			if len(cfg.Address) > 0 {
				vcfg.Address = cfg.Address
			}
			vcfg.Token = cfg.Token
			vcfg.Namespace = cfg.Namespace

			sp, err := secrets.NewVaultSecretProviderFromConfig(vcfg)
			if err != nil {
				return err
			}

			keys[keyConfig.Kind] = sp
		}
	}

	return nil
}

func (kp *KeyProvider) PrepareForDecode(data interface{}) error {
	if kp.Kind != "" {
		// this instance was already prepared from a previous call
		return nil
	}
	kind := getKindFromUnstructured(data)
	switch kind {
	case "vault":
		kp.Config = VaultConfig{}
	case "awskms":
		kp.Config = AWSKMSConfig{}
	case "native":
		kp.Config = nativeKeyProviderConfig{}
	default:
		// unknown kind error is handled by import importKeyProviders
	}

	return nil
}

type SecretProvider struct {
	Kind   string      `config:"kind"`
	Name   string      `config:"name"`
	Config interface{} // contains secret-provider-specific config
}

var baseSecretStorageKinds = []string{
	"env",
	"file",
	"plaintext",
	"kubernetes",
}

func isABaseSecretStorageKind(s string) bool {
	for _, item := range baseSecretStorageKinds {
		if item == s {
			return true
		}
	}

	return false
}

func importSecrets(cfg []SecretProvider, storage map[string]secrets.SecretStorage) error {
	loadSecretConfig := func(secret SecretProvider) (err error) {
		name := secret.Name
		if len(name) == 0 {
			name = secret.Kind
		}

		if _, found := storage[name]; found {
			return fmt.Errorf("duplicate secret configuration for %q, please provide a unique name for this secret configuration", name)
		}

		switch secret.Kind {
		case "vault":
			cfg, ok := secret.Config.(VaultConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be VaultConfig, but was %t", secret.Config)
			}

			cfg.Token, err = secrets.GetSecret(cfg.Token, storage)
			if err != nil {
				return err
			}

			vcfg := secrets.NewVaultConfig()
			if len(cfg.TransitMount) > 0 {
				vcfg.TransitMount = cfg.TransitMount
			}
			if len(cfg.SecretMount) > 0 {
				vcfg.SecretMount = cfg.SecretMount
			}
			if len(cfg.Address) > 0 {
				vcfg.Address = cfg.Address
			}
			vcfg.Token = cfg.Token
			vcfg.Namespace = cfg.Namespace

			vault, err := secrets.NewVaultSecretProviderFromConfig(vcfg)
			if err != nil {
				return fmt.Errorf("creating vault provider: %w", err)
			}

			storage[name] = vault
		case "awsssm":
			cfg, ok := secret.Config.(AWSSSMConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be AWSSSMConfig, but was %t", secret.Config)
			}

			cfg.AccessKeyID, err = secrets.GetSecret(cfg.AccessKeyID, storage)
			if err != nil {
				return err
			}

			cfg.SecretAccessKey, err = secrets.GetSecret(cfg.SecretAccessKey, storage)
			if err != nil {
				return err
			}

			ssmcfg := secrets.AWSSSMConfig{
				AWSConfig: secrets.AWSConfig{
					Endpoint:        cfg.Endpoint,
					Region:          cfg.Region,
					AccessKeyID:     cfg.AccessKeyID,
					SecretAccessKey: cfg.SecretAccessKey,
				},
				KeyID: cfg.KeyID,
			}

			ssm, err := secrets.NewAWSSSMSecretProviderFromConfig(ssmcfg)
			if err != nil {
				return fmt.Errorf("creating aws ssm: %w", err)
			}

			storage[name] = ssm
		case "awssecretsmanager":
			cfg, ok := secret.Config.(AWSSecretsManagerConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be AWSSecretsManagerConfig, but was %t", secret.Config)
			}

			cfg.AccessKeyID, err = secrets.GetSecret(cfg.AccessKeyID, storage)
			if err != nil {
				return err
			}

			cfg.SecretAccessKey, err = secrets.GetSecret(cfg.SecretAccessKey, storage)
			if err != nil {
				return err
			}

			smCfg := secrets.AWSSecretsManagerConfig{
				AWSConfig: secrets.AWSConfig{
					Endpoint:        cfg.Endpoint,
					Region:          cfg.Region,
					AccessKeyID:     cfg.AccessKeyID,
					SecretAccessKey: cfg.SecretAccessKey,
				},
			}

			sm, err := secrets.NewAWSSecretsManagerFromConfig(smCfg)
			if err != nil {
				return fmt.Errorf("creating aws sm: %w", err)
			}

			storage[name] = sm
		case "kubernetes":
			cfg, ok := secret.Config.(KubernetesConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be KubernetesConfig, but was %t", secret.Config)
			}

			kcfg := secrets.NewKubernetesConfig()
			if len(cfg.Namespace) > 0 {
				kcfg.Namespace = cfg.Namespace
			}

			k8s, err := secrets.NewKubernetesSecretProviderFromConfig(kcfg)
			if err != nil {
				return fmt.Errorf("creating k8s secret provider: %w", err)
			}

			storage[name] = k8s
		case "env":
			cfg, ok := secret.Config.(GenericConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be GenericConfig, but was %t", secret.Config)
			}

			gcfg := secrets.GenericConfig{
				Base64:           cfg.Base64,
				Base64URLEncoded: cfg.Base64URLEncoded,
				Base64Raw:        cfg.Base64Raw,
			}

			f := secrets.NewEnvSecretProviderFromConfig(gcfg)
			storage[name] = f
		case "file":
			cfg, ok := secret.Config.(FileConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be FileConfig, but was %t", secret.Config)
			}

			fcfg := secrets.FileConfig{
				GenericConfig: secrets.GenericConfig{
					Base64:           cfg.Base64,
					Base64URLEncoded: cfg.Base64URLEncoded,
					Base64Raw:        cfg.Base64Raw,
				},
				Path: cfg.Path,
			}

			f := secrets.NewFileSecretProviderFromConfig(fcfg)
			storage[name] = f
		case "plaintext", "":
			cfg, ok := secret.Config.(GenericConfig)
			if !ok {
				return fmt.Errorf("expected secret config to be GenericConfig, but was %t", secret.Config)
			}

			gcfg := secrets.GenericConfig{
				Base64:           cfg.Base64,
				Base64URLEncoded: cfg.Base64URLEncoded,
				Base64Raw:        cfg.Base64Raw,
			}

			f := secrets.NewPlainSecretProviderFromConfig(gcfg)
			storage[name] = f
		default:
			return fmt.Errorf("unknown secret provider type %q", secret.Kind)
		}

		return nil
	}

	// check all base types first
	for _, secret := range cfg {
		if !isABaseSecretStorageKind(secret.Kind) {
			continue
		}

		if err := loadSecretConfig(secret); err != nil {
			return err
		}
	}

	if err := loadDefaultSecretConfig(storage); err != nil {
		return err
	}

	// now load non-base types which might depend on them.
	for _, secret := range cfg {
		if isABaseSecretStorageKind(secret.Kind) {
			continue
		}

		if err := loadSecretConfig(secret); err != nil {
			return err
		}
	}

	return nil
}

// loadDefaultSecretConfig loads configuration for types that should be available,
// assuming the user didn't override the configuration for them.
func loadDefaultSecretConfig(storage map[string]secrets.SecretStorage) error {
	// set up the default supported types
	if _, found := storage["env"]; !found {
		f := secrets.NewEnvSecretProviderFromConfig(secrets.GenericConfig{})
		storage["env"] = f
	}

	if _, found := storage["file"]; !found {
		f := secrets.NewFileSecretProviderFromConfig(secrets.FileConfig{})
		storage["file"] = f
	}

	if _, found := storage["plaintext"]; !found {
		f := secrets.NewPlainSecretProviderFromConfig(secrets.GenericConfig{})
		storage["plaintext"] = f
	}

	if _, found := storage["kubernetes"]; !found {
		// only setup k8s automatically if KUBERNETES_SERVICE_HOST is defined; ie, we are in the clustes.
		if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
			k8s, err := secrets.NewKubernetesSecretProviderFromConfig(secrets.NewKubernetesConfig())
			if err != nil {
				return fmt.Errorf("creating k8s secret provider: %w", err)
			}

			storage["kubernetes"] = k8s
		}
	}

	return nil
}

// PrepareForDecode prepares the SecretProvider for mapstructure.Decode by
// setting a concrete type for the config based on the kind. Failures to decode
// will be handled by mapstructure, or by importSecrets.
func (sp *SecretProvider) PrepareForDecode(data interface{}) error {
	if sp.Kind != "" {
		// this instance was already prepared from a previous call
		return nil
	}
	kind := getKindFromUnstructured(data)
	switch kind {
	case "vault":
		sp.Config = VaultConfig{}
	case "awsssm":
		sp.Config = AWSSSMConfig{}
	case "awssecretsmanager":
		sp.Config = AWSSecretsManagerConfig{}
	case "kubernetes":
		sp.Config = KubernetesConfig{}
	case "env":
		sp.Config = GenericConfig{}
	case "file":
		sp.Config = FileConfig{}
	case "plaintext", "":
		sp.Kind = "plaintext"
		sp.Config = GenericConfig{}
	default:
		// unknown kind error is handled by importSecrets
	}

	return nil
}

func getKindFromUnstructured(data interface{}) string {
	switch raw := data.(type) {
	case map[string]interface{}:
		if v, ok := raw["kind"].(string); ok {
			return v
		}
	case map[interface{}]interface{}:
		if v, ok := raw["kind"].(string); ok {
			return v
		}
	case *SecretProvider:
		return raw.Kind
	}
	return ""
}

func (s Server) loadConfig(config Config) error {
	if err := validator.New().Struct(config); err != nil {
		return err
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		// inject internal infra provider
		config.Providers = append(config.Providers, Provider{
			Name: models.InternalInfraProviderName,
			Kind: models.ProviderKindInfra.String(),
		})

		config.Users = append(config.Users, User{
			Name: models.InternalInfraConnectorIdentityName,
		})

		config.Grants = append(config.Grants, Grant{
			User:     models.InternalInfraConnectorIdentityName,
			Role:     models.InfraConnectorRole,
			Resource: "infra",
		})

		if err := s.loadProviders(tx, config.Providers); err != nil {
			return fmt.Errorf("load providers: %w", err)
		}

		// extract users from grants and add them to users
		for _, g := range config.Grants {
			switch {
			case g.User != "":
				config.Users = append(config.Users, User{Name: g.User})
			case g.Machine != "":
				logging.Warnf("please update 'machine' grant to 'user', the 'machine' grant type is deprecated and will be removed in a future release")
				config.Users = append(config.Users, User{Name: g.Machine})
			}
		}

		if err := s.loadUsers(tx, config.Users); err != nil {
			return fmt.Errorf("load users: %w", err)
		}

		if err := s.loadGrants(tx, config.Grants); err != nil {
			return fmt.Errorf("load grants: %w", err)
		}

		return nil
	})
}

func (s Server) loadProviders(db *gorm.DB, providers []Provider) error {
	keep := []uid.ID{}

	for _, p := range providers {
		provider, err := s.loadProvider(db, p)
		if err != nil {
			return err
		}

		keep = append(keep, provider.ID)
	}

	// remove any provider previously defined by config
	if err := data.DeleteProviders(db, data.NotIDs(keep), data.CreatedBy(models.CreatedBySystem)); err != nil {
		return err
	}

	return nil
}

func (Server) loadProvider(db *gorm.DB, input Provider) (*models.Provider, error) {
	// provider kind is an optional field
	kind, err := models.ParseProviderKind(input.Kind)
	if err != nil {
		return nil, fmt.Errorf("could not parse provider in config load: %w", err)
	}

	provider, err := data.GetProvider(db, data.ByName(input.Name))
	if err != nil {
		if !errors.Is(err, internal.ErrNotFound) {
			return nil, err
		}

		provider := &models.Provider{
			Name:         input.Name,
			URL:          input.URL,
			ClientID:     input.ClientID,
			ClientSecret: models.EncryptedAtRest(input.ClientSecret),
			AuthURL:      input.AuthURL,
			Scopes:       input.Scopes,
			Kind:         kind,
			CreatedBy:    models.CreatedBySystem,
		}

		if provider.Kind != models.ProviderKindInfra {
			// only call the provider to resolve info if it is not known
			if input.AuthURL == "" && len(input.Scopes) == 0 {
				providerClient := providers.NewOIDCClient(*provider, input.ClientSecret, "http://localhost:8301")
				authServerInfo, err := providerClient.AuthServerInfo(context.Background())
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return nil, fmt.Errorf("%w: %s", internal.ErrBadGateway, err)
					}
					return nil, err
				}

				provider.AuthURL = authServerInfo.AuthURL
				provider.Scopes = authServerInfo.ScopesSupported
			}

			// check that the scopes we need are set
			supportedScopes := make(map[string]bool)
			for _, s := range provider.Scopes {
				supportedScopes[s] = true
			}
			if !supportedScopes["openid"] || !supportedScopes["email"] {
				return nil, fmt.Errorf("required scopes 'openid' and 'email' not found on provider %q", input.Name)
			}
		}

		if err := data.CreateProvider(db, provider); err != nil {
			return nil, err
		}

		return provider, nil
	}

	// provider already exists, update it
	provider.URL = input.URL
	provider.ClientID = input.ClientID
	provider.ClientSecret = models.EncryptedAtRest(input.ClientSecret)
	provider.Kind = kind

	if err := data.SaveProvider(db, provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (s Server) loadGrants(db *gorm.DB, grants []Grant) error {
	keep := make([]uid.ID, 0, len(grants))

	for _, g := range grants {
		grant, err := s.loadGrant(db, g)
		if err != nil {
			return err
		}

		keep = append(keep, grant.ID)
	}

	// remove any grant previously defined by config
	if err := data.DeleteGrants(db, data.NotIDs(keep), data.CreatedBy(models.CreatedBySystem)); err != nil {
		return err
	}

	return nil
}

func (Server) loadGrant(db *gorm.DB, input Grant) (*models.Grant, error) {
	var id uid.PolymorphicID

	switch {
	case input.User != "":
		user, err := data.GetIdentity(db, data.ByName(input.User))
		if err != nil {
			return nil, err
		}

		id = uid.NewIdentityPolymorphicID(user.ID)

	case input.Group != "":
		group, err := data.GetGroup(db, data.ByName(input.Group))
		if err != nil {
			if !errors.Is(err, internal.ErrNotFound) {
				return nil, err
			}

			logging.Debugf("creating placeholder group %q", input.Group)

			// group does not exist yet, create a placeholder
			group = &models.Group{
				Name:      input.Group,
				CreatedBy: models.CreatedBySystem,
			}

			if err := data.CreateGroup(db, group); err != nil {
				return nil, err
			}
		}

		id = uid.NewGroupPolymorphicID(group.ID)

	// TODO: remove this when deprecated machines in config are removed
	case input.Machine != "":
		machine, err := data.GetIdentity(db, data.ByName(input.Machine))
		if err != nil {
			return nil, err
		}

		id = uid.NewIdentityPolymorphicID(machine.ID)

	default:
		return nil, errors.New("invalid grant: missing identity")
	}

	if len(input.Role) == 0 {
		input.Role = models.BasePermissionConnect
	}

	grant, err := data.GetGrant(db, data.BySubject(id), data.ByResource(input.Resource), data.ByPrivilege(input.Role))
	if err != nil {
		if !errors.Is(err, internal.ErrNotFound) {
			return nil, err
		}

		grant = &models.Grant{
			Subject:   id,
			Resource:  input.Resource,
			Privilege: input.Role,
			CreatedBy: models.CreatedBySystem,
		}

		if err := data.CreateGrant(db, grant); err != nil {
			return nil, err
		}
	}

	return grant, nil
}

func (s Server) loadUsers(db *gorm.DB, users []User) error {
	keep := make([]uid.ID, 0, len(users)+1)

	for _, i := range users {
		user, err := s.loadUser(db, i)
		if err != nil {
			return err
		}

		keep = append(keep, user.ID)
	}

	// remove any users previously defined by config
	if err := data.DeleteIdentities(db, data.NotIDs(keep), data.CreatedBy(models.CreatedBySystem)); err != nil {
		return err
	}

	return nil
}

func (s Server) loadUser(db *gorm.DB, input User) (*models.Identity, error) {
	name := input.Name
	if name == "" {
		if input.Email != "" {
			logging.Warnf("please update 'email' config identity to 'name', the 'email' identity label is deprecated and will be removed in a future release")
			name = input.Email
		}
	}

	identity, err := data.GetIdentity(db, data.ByName(name))
	if err != nil {
		if !errors.Is(err, internal.ErrNotFound) {
			return nil, err
		}

		if name != models.InternalInfraConnectorIdentityName {
			_, err := mail.ParseAddress(name)
			if err != nil {
				logging.Warnf("user name %q in server configuration is not a valid email, please update this name to a valid email", name)
			}
		}

		identity = &models.Identity{
			Name:      name,
			CreatedBy: models.CreatedBySystem,
		}

		if err := data.CreateIdentity(db, identity); err != nil {
			return nil, err
		}
	}

	if err := s.loadCredential(db, identity, input.Password); err != nil {
		return nil, err
	}

	if err := s.loadAccessKey(db, identity, input.AccessKey); err != nil {
		return nil, err
	}

	return identity, nil
}

func (s Server) loadCredential(db *gorm.DB, identity *models.Identity, password string) error {
	if password == "" {
		return nil
	}

	password, err := secrets.GetSecret(password, s.secrets)
	if err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	credential, err := data.GetCredential(db, data.ByIdentityID(identity.ID))
	if err != nil {
		if !errors.Is(err, internal.ErrNotFound) {
			return err
		}

		credential := &models.Credential{
			IdentityID:   identity.ID,
			PasswordHash: hash,
		}

		if err := data.CreateCredential(db, credential); err != nil {
			return err
		}

		if _, err := data.CreateProviderUser(db, data.InfraProvider(db), identity); err != nil {
			return err
		}

		return nil
	}

	credential.PasswordHash = hash

	if err := data.SaveCredential(db, credential); err != nil {
		return err
	}

	return nil
}

func (s Server) loadAccessKey(db *gorm.DB, identity *models.Identity, key string) error {
	if key == "" {
		return nil
	}

	key, err := secrets.GetSecret(key, s.secrets)
	if err != nil {
		return err
	}

	keyID, secret, ok := strings.Cut(key, ".")
	if !ok {
		return fmt.Errorf("invalid access key format")
	}

	accessKey, err := data.GetAccessKey(db, data.ByKeyID(keyID))
	if err != nil {
		if !errors.Is(err, internal.ErrNotFound) {
			return err
		}

		accessKey := &models.AccessKey{
			IssuedFor:  identity.ID,
			ExpiresAt:  time.Now().AddDate(10, 0, 0),
			KeyID:      keyID,
			Secret:     secret,
			ProviderID: data.InfraProvider(db).ID,
		}

		if _, err := data.CreateAccessKey(db, accessKey); err != nil {
			return err
		}

		if _, err := data.CreateProviderUser(db, data.InfraProvider(db), identity); err != nil {
			return err
		}

		return nil
	}

	if accessKey.IssuedFor != identity.ID {
		return fmt.Errorf("access key assigned to %q is already assigned to another user, a user's access key must have a unique ID", identity.Name)
	}

	accessKey.Secret = secret

	if err := data.SaveAccessKey(db, accessKey); err != nil {
		return err
	}

	return nil
}
