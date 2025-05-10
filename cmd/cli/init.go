package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/spf13/cobra"
)

func initAskUser(prompt string, reader *bufio.Reader) (string, error) {
	fmt.Println(prompt)
	ans, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading user input: %v", err)
	}

	return strings.TrimSpace(ans), nil
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "initialize the Zerolarec client",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		apiEndpoint, err := askUser("Enter the API endpoint (default: localhost:8080)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading user input: %v\n", err))
		}
		if apiEndpoint == "" {
			apiEndpoint = "localhost:8080"
		}

		client, err := newClient(apiEndpoint)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		useExistingAccount, err := askUserForBool("Do you want to use existing account?")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading existing account: %v\n", err))
		}
		var config *Config
		if useExistingAccount {
			config, err = initLogin(ctx, client)
		} else {
			config, err = initRegister(ctx, client)
		}

		if err != nil {
			printFatalMessage(fmt.Sprintf("error initializing account: %v\n", err))
		}

		printMessage("Generating config file...")

		if err := saveConfig(config); err != nil {
			printFatalMessage(fmt.Sprintf("error saving config: %v\n", err))
		}

		printMessage("Config file generated successfully")
		printMessage("Initialized successfully")

	},
}

func initLogin(ctx context.Context, client *client) (*Config, error) {
	login, err := askUser("Enter your login")
	if err != nil {
		return nil, fmt.Errorf("error reading login: %v\n", err)
	}

	password, err := askUser("Enter your password")
	if err != nil {
		return nil, fmt.Errorf("error reading password: %v\n", err)
	}

	privateKeyStr, err := askUserKey("Enter your private key")
	if err != nil {
		return nil, fmt.Errorf("error reading private key: %v\n", err)
	}

	privateKey, err := unmarshalPrivateKey([]byte(privateKeyStr))
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling private key: %v\n", err)
	}

	printMessage("Logging in...")
	response, err := client.authClient.Login(ctx, &apiv1.LoginRequest{
		Login:    login,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("error logging in: %v\n", err)
	}

	respPublicKey, err := unmarshalPublicKey(response.User.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling public key: %v\n", err)
	}

	if privateKey.PublicKey.N.Cmp(respPublicKey.N) != 0 {
		return nil, fmt.Errorf("error mismatching public keys, please check your private key")
	}

	printMessage("Logged in successfully")

	return &Config{
		ApiEndpoint: client.apiEndpoint,
		Login:       login,
		Password:    password,
		PublicKey:   string(response.User.PublicKey),
		PrivateKey:  string(privateKeyStr),
	}, nil
}

func initRegister(ctx context.Context, client *client) (*Config, error) {
	login, err := askUser("Enter your login: ")
	if err != nil {
		return nil, fmt.Errorf("error reading login: %v\n", err)
	}

	password, err := askUser("Enter your password: ")
	if err != nil {
		return nil, fmt.Errorf("error reading password: %v\n", err)
	}

	fmt.Println("Generating rsa key pair...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v\n", err)
	}

	marshaledPublicKey, err := marshalPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %v\n", err)
	}

	marshaledPrivateKey, err := marshalPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling private key: %v\n", err)
	}

	printMessage("rsa key pair generated")

	printMessage("Registering new user...")
	_, err = client.authClient.Register(ctx, &apiv1.RegisterRequest{
		Login:     login,
		Password:  password,
		PublicKey: marshaledPublicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("error registering: %v\n", err)
	}

	printMessage("Registered successfully")

	return &Config{
		ApiEndpoint: client.apiEndpoint,
		Login:       login,
		Password:    password,
		PublicKey:   string(marshaledPublicKey),
		PrivateKey:  string(marshaledPrivateKey),
	}, nil
}
