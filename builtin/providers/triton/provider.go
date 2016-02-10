package triton

import (
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/joyent/gocommon/client"
	"github.com/joyent/gosdc/cloudapi"
	"github.com/joyent/gosign/auth"
)

// Provider returns a terraform.ResourceProvider.
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"account": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SDC_ACCOUNT", ""),
			},

			"url": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SDC_URL", "https://us-west-1.api.joyentcloud.com"),
			},

			"key_path": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SDC_KEY_PATH", ""),
			},

			"key_material": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SDC_KEY_MATERIAL", ""),
			},

			"key_id": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SDC_KEY_ID", ""),
			},
		},

		ResourcesMap:  map[string]*schema.Resource{},
		ConfigureFunc: providerConfigure,
	}
}

type SDCConfig struct {
	Account string
	KeyPath string
	KeyID   string
	URL     string
}

func (c SDCConfig) validate() error {
	var err *multierror.Error

	if c.URL == "" {
		err = multierror.Append(err, fmt.Errorf("URL must be configured for the Triton provider"))
	}
	if c.KeyPath == "" {
		err = multierror.Append(err, fmt.Errorf("Key Path must be configured for the Triton provider"))
	}
	if c.KeyID == "" {
		err = multierror.Append(err, fmt.Errorf("Key ID must be configured for the Triton provider"))
	}
	if c.Account == "" {
		err = multierror.Append(err, fmt.Errorf("Account must be configured for the Triton provider"))
	}

	return err.ErrorOrNil()
}

func (c SDCConfig) getSDCClient() (*cloudapi.Client, error) {
	keyData, err := ioutil.ReadFile(c.KeyPath)
	if err != nil {
		return nil, err
	}

	userauth, err := auth.NewAuth(c.Account, string(keyData), "rsa-sha256")
	if err != nil {
		return nil, err
	}

	creds := &auth.Credentials{
		UserAuthentication: userauth,
		SdcKeyId:           c.KeyID,
		SdcEndpoint:        auth.Endpoint{URL: c.URL},
	}

	client := cloudapi.New(client.NewClient(
		c.URL,
		cloudapi.DefaultAPIVersion,
		creds,
		&cloudapi.Logger,
	))

	return client, nil
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := SDCConfig{
		Account: d.Get("account").(string),
		URL:     d.Get("url").(string),
		KeyPath: d.Get("key_path").(string),
		KeyID:   d.Get("key_id").(string),
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	client, err := config.getSDCClient()
	if err != nil {
		return nil, err
	}

	return client, nil
}
