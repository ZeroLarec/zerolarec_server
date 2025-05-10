package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"gopkg.in/yaml.v3"
)

func toMessageString(message string) string {
	return fmt.Sprintf("\033[1m%s\033[0m", message)
}

func printFatalMessage(message string) {
	printMessage(fmt.Sprintf("error: %s\n", message))
	os.Exit(1)
}

func printMessage(message string) {
	fmt.Println(toMessageString(message))
}

func askUser(prompt string) (string, error) {
	fmt.Printf("%s\n> ", toMessageString(prompt))
	ans, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading user input: %v", err)
	}

	return strings.TrimSpace(ans), nil
}

func askUserForBool(prompt string) (bool, error) {
	ans, err := askUser(fmt.Sprintf("%s (y/n)", prompt))
	if err != nil {
		return false, fmt.Errorf("error reading user input: %v", err)
	}

	switch {
	case regexp.MustCompile(`^y|Y|yes|YES`).MatchString(ans):
		return true, nil
	case regexp.MustCompile(`^n|N|no|NO`).MatchString(ans):
		return false, nil
	default:
		return false, fmt.Errorf("invalid input: %s", ans)
	}
}

func askUserForKeyValues(prompt string) (map[string]string, error) {
	printMessage(prompt)
	printMessage("Enter key-value pairs (one per line, format: key: value)")
	printMessage("Press Ctrl+D to finish input")

	result := make(map[string]string)
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Split the line by : to get key and value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format: expected key: value, got %s", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			return nil, fmt.Errorf("key cannot be empty")
		}

		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %v", err)
	}

	return result, nil
}

type Config struct {
	ApiEndpoint string `yaml:"api_endpoint"`
	Login       string `yaml:"login"`
	Password    string `yaml:"password"`
	PublicKey   string `yaml:"public_key"`
	PrivateKey  string `yaml:"private_key"`
}

func loadConfig() (*Config, error) {

	yamlConfig, err := os.ReadFile(configPathFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(yamlConfig, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &config, nil
}

func askUserKey(message string) (string, error) {
	printMessage(message)
	printMessage("after message print ctrl+d to end input")
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading input: %w", err)
	}
	return strings.Join(lines, "\n"), nil
}

func saveConfig(config *Config) error {

	yamlConfig, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(configPathFlag, yamlConfig, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

type client struct {
	apiEndpoint      string
	healthClient     apiv1.HealthServiceClient
	userClient       apiv1.UserServiceClient
	authClient       apiv1.AuthenticateServiceClient
	vaultClient      apiv1.VaultServiceClient
	secretClient     apiv1.SecretServiceClient
	accessRuleClient apiv1.AccessRuleServiceClient
}

func newClient(apiEndpoint string) (*client, error) {
	conn, err := grpc.NewClient(apiEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("error creating connection: %v", err)
	}

	return &client{
		apiEndpoint:      apiEndpoint,
		healthClient:     apiv1.NewHealthServiceClient(conn),
		userClient:       apiv1.NewUserServiceClient(conn),
		authClient:       apiv1.NewAuthenticateServiceClient(conn),
		vaultClient:      apiv1.NewVaultServiceClient(conn),
		secretClient:     apiv1.NewSecretServiceClient(conn),
		accessRuleClient: apiv1.NewAccessRuleServiceClient(conn),
	}, nil
}

func newLoggedClient(ctx context.Context, apiEndpoint, login, password string) (context.Context, *client, error) {
	client, err := newClient(apiEndpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating client: %v", err)
	}

	response, err := client.authClient.Login(ctx, &apiv1.LoginRequest{
		Login:    login,
		Password: password,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error logging in: %v", err)
	}

	return metadata.NewOutgoingContext(ctx, metadata.New(map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", response.AccessToken),
	})), client, nil
}
