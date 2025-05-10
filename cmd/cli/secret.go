package main

import (
	"context"
	"fmt"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(secretCmd)
	secretCmd.AddCommand(listSecretsCmd)
	secretCmd.AddCommand(getSecretCmd)
	secretCmd.AddCommand(createSecretCmd)
	secretCmd.AddCommand(updateSecretCmd)
	secretCmd.AddCommand(deleteSecretCmd)
}

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "secret",
}

func encryptKeyValues(keyValues map[string]string, vaultKey []byte) (map[string][]byte, error) {
	encryptedKeyValues := make(map[string][]byte, len(keyValues))

	for key, value := range keyValues {
		encryptedValue, err := encryptAES([]byte(value), vaultKey)
		if err != nil {
			return nil, fmt.Errorf("error encrypting key value: %v", err)
		}
		encryptedKeyValues[key] = encryptedValue
	}

	return encryptedKeyValues, nil
}

func decryptKeyValues(keyValues map[string][]byte, vaultKey []byte) (map[string]string, error) {
	decryptedKeyValues := make(map[string]string, len(keyValues))

	for key, value := range keyValues {
		decryptedValue, err := decryptAES(value, vaultKey)
		if err != nil {
			return nil, fmt.Errorf("error decrypting key value: %v", err)
		}
		decryptedKeyValues[key] = string(decryptedValue)
	}

	return decryptedKeyValues, nil
}

type secret struct {
	id          string
	name        string
	description string
	keyValues   map[string]string
}

func printSecrets(secret []*secret) {
	printMessage("--------------------------------")
	for _, s := range secret {
		printMessage(fmt.Sprintf("secret-id: %s", s.id))
		printMessage(fmt.Sprintf("name: %s", s.name))
		printMessage(fmt.Sprintf("description: %s", s.description))
		printMessage("key-values:")
		for key, value := range s.keyValues {
			printMessage(fmt.Sprintf("    %s: %s", key, value))
		}
		printMessage("--------------------------------")
	}
}

var listSecretsCmd = &cobra.Command{
	Use:   "list",
	Short: "list secrets",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error loading config: %v\n", err))
		}

		ctx, client, err := newLoggedClient(ctx, config.ApiEndpoint, config.Login, config.Password)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		vaultID, err := askUser("Enter vault id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault id: %v\n", err))
		}
		vaultKey, err := getVaultKey(ctx, client, vaultID, config.PrivateKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting vault key: %v\n", err))
		}

		response, err := client.secretClient.ListSecrets(ctx, &apiv1.ListSecretsRequest{
			VaultId: vaultID,
			Limit:   100,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error listing secrets: %v\n", err))
		}

		decryptedSecrets := make([]*secret, 0, len(response.Secrets))
		for _, encryptedSecret := range response.Secrets {
			decryptedKeyValues, err := decryptKeyValues(encryptedSecret.KeyValues.KeyValues, vaultKey)
			if err != nil {
				printFatalMessage(fmt.Sprintf("error decrypting key values: %v\n", err))
			}
			decryptedSecrets = append(decryptedSecrets, &secret{
				id:          encryptedSecret.SecretId,
				name:        encryptedSecret.Name,
				description: encryptedSecret.Description,
				keyValues:   decryptedKeyValues,
			})
		}
		printSecrets(decryptedSecrets)
	},
}

var getSecretCmd = &cobra.Command{
	Use:   "get",
	Short: "get secret",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error loading config: %v\n", err))
		}

		ctx, client, err := newLoggedClient(ctx, config.ApiEndpoint, config.Login, config.Password)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		vaultID, err := askUser("Enter vault id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault id: %v\n", err))
		}

		vaultKey, err := getVaultKey(ctx, client, vaultID, config.PrivateKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting vault key: %v\n", err))
		}

		secretID, err := askUser("Enter secret id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret id: %v\n", err))
		}

		response, err := client.secretClient.GetSecret(ctx, &apiv1.GetSecretRequest{
			VaultId:  vaultID,
			SecretId: secretID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting secret: %v\n", err))
		}

		decryptedKeyValues, err := decryptKeyValues(response.KeyValues.KeyValues, vaultKey)

		secrets := []*secret{
			{
				id:          response.SecretId,
				name:        response.Name,
				description: response.Description,
				keyValues:   decryptedKeyValues,
			},
		}

		printSecrets(secrets)
	},
}

var createSecretCmd = &cobra.Command{
	Use:   "create",
	Short: "create secret",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error loading config: %v\n", err))
		}

		ctx, client, err := newLoggedClient(ctx, config.ApiEndpoint, config.Login, config.Password)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		vaultID, err := askUser("Enter vault id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault id: %v\n", err))
		}

		vaultKey, err := getVaultKey(ctx, client, vaultID, config.PrivateKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting vault key: %v\n", err))
		}

		name, err := askUser("Enter secret name")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret name: %v\n", err))
		}

		description, err := askUser("Enter secret description (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret description: %v\n", err))
		}

		keyValues, err := askUserForKeyValues("Enter secret key values")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret key values: %v\n", err))
		}

		encryptedKeyValues, err := encryptKeyValues(keyValues, vaultKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error encrypting secret key values: %v\n", err))
		}

		_, err = client.secretClient.CreateSecret(ctx, &apiv1.CreateSecretRequest{
			VaultId:     vaultID,
			Name:        name,
			Description: description,
			KeyValues: &apiv1.KeyValues{
				KeyValues: encryptedKeyValues,
			},
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating secret: %v\n", err))
		}

		printMessage("secret created successfully")
	},
}

var updateSecretCmd = &cobra.Command{
	Use:   "update",
	Short: "update secret",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error loading config: %v\n", err))
		}

		ctx, client, err := newLoggedClient(ctx, config.ApiEndpoint, config.Login, config.Password)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		vaultID, err := askUser("Enter vault id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault id: %v\n", err))
		}

		vaultKey, err := getVaultKey(ctx, client, vaultID, config.PrivateKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting vault key: %v\n", err))
		}

		secretID, err := askUser("Enter secret id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret id: %v\n", err))
		}

		req := &apiv1.UpdateSecretRequest{
			VaultId:  vaultID,
			SecretId: secretID,
		}

		nameToUpdate, err := askUser("Enter secret name (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret name: %v\n", err))
		}
		if nameToUpdate != "" {
			req.Name = &nameToUpdate
		}

		descriptionToUpdate, err := askUser("Enter secret description (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret description: %v\n", err))
		}
		if descriptionToUpdate != "" {
			req.Description = &descriptionToUpdate
		}

		updateKeyValues, err := askUserForBool("Update key values")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading update key values: %v\n", err))
		}

		if updateKeyValues {
			keyValuesToUpdate, err := askUserForKeyValues("Enter secret key values to update")
			if err != nil {
				printFatalMessage(fmt.Sprintf("error reading secret key values to update: %v\n", err))
			}
			encryptedKeyValues, err := encryptKeyValues(keyValuesToUpdate, vaultKey)
			if err != nil {
				printFatalMessage(fmt.Sprintf("error encrypting secret key values: %v\n", err))
			}
			req.KeyValues = &apiv1.KeyValues{
				KeyValues: encryptedKeyValues,
			}
		}

		_, err = client.secretClient.UpdateSecret(ctx, req)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error updating secret: %v\n", err))
		}

		printMessage("secret updated successfully")
	},
}

var deleteSecretCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete secret",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error loading config: %v\n", err))
		}

		ctx, client, err := newLoggedClient(ctx, config.ApiEndpoint, config.Login, config.Password)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		vaultID, err := askUser("Enter vault id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault id: %v\n", err))
		}

		secretID, err := askUser("Enter secret id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret id: %v\n", err))
		}

		_, err = client.secretClient.DeleteSecret(ctx, &apiv1.DeleteSecretRequest{
			VaultId:  vaultID,
			SecretId: secretID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error deleting secret: %v\n", err))
		}

		printMessage("secret deleted successfully")
	},
}
