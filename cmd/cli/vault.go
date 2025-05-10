package main

import (
	"context"
	"fmt"
	"time"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/spf13/cobra"
)

func printVaults(vaults []*apiv1.Vault) {
	printMessage("------------------------------------------------")
	for _, vault := range vaults {
		printMessage(fmt.Sprintf("|vault-id:  | %s", vault.VaultId))
		printMessage(fmt.Sprintf("|name:      | %s", vault.Name))
		printMessage(fmt.Sprintf("|description| %s", vault.Description))
		printMessage(fmt.Sprintf("|created-at | %s", vault.CreatedAt.AsTime().Format(time.RFC1123)))
		printMessage(fmt.Sprintf("|updated-at | %s", vault.UpdatedAt.AsTime().Format(time.RFC1123)))
		printMessage("------------------------------------------------")
	}
}

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(listVaultsCmd)
	vaultCmd.AddCommand(getVaultCmd)
	vaultCmd.AddCommand(createVaultCmd)
	vaultCmd.AddCommand(updateVaultCmd)
	vaultCmd.AddCommand(deleteVaultCmd)
	vaultCmd.AddCommand(listVaultMembersCmd)
	vaultCmd.AddCommand(addVaultMemberCmd)
	vaultCmd.AddCommand(removeVaultMemberCmd)
}

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "vault management",
}

var listVaultsCmd = &cobra.Command{
	Use:   "list",
	Short: "list vaults",
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

		response, err := client.vaultClient.ListVaults(ctx, &apiv1.ListVaultsRequest{
			Limit: 100,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error listing vaults: %v\n", err))
		}

		printMessage("vaults:")
		printVaults(response.Vaults)
	},
}

var getVaultCmd = &cobra.Command{
	Use:   "get",
	Short: "get vault",
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

		response, err := client.vaultClient.GetVault(ctx, &apiv1.GetVaultRequest{
			VaultId: vaultID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting vault: %v\n", err))
		}

		printMessage("vault:")
		printVaults([]*apiv1.Vault{response})
	},
}

var createVaultCmd = &cobra.Command{
	Use:   "create",
	Short: "create vault",
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

		vaultKey, err := generateAESKey()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error generating vault key: %v\n", err))
		}

		publicKey, err := unmarshalPublicKey([]byte(config.PublicKey))
		if err != nil {
			printFatalMessage(fmt.Sprintf("error unmarshalling public key: %v\n", err))
		}

		vaultKeyProtected, err := rsaEncrypt(publicKey, vaultKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error encrypting vault key: %v\n", err))
		}

		name, err := askUser("Enter vault name")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault name: %v\n", err))
		}

		description, err := askUser("Enter vault description (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault description: %v\n", err))
		}

		response, err := client.vaultClient.CreateVault(ctx, &apiv1.CreateVaultRequest{
			Name:              name,
			Description:       description,
			VaultKeyProtected: vaultKeyProtected,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating vault: %v\n", err))
		}

		printMessage("vault created successfully:")
		printVaults([]*apiv1.Vault{response})

	},
}

var updateVaultCmd = &cobra.Command{
	Use:   "update",
	Short: "update vault",
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

		var nameToUpdate *string
		name, err := askUser("Enter vault name (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault name: %v\n", err))
		}
		if name != "" {
			nameToUpdate = &name
		}

		var descriptionToUpdate *string
		description, err := askUser("Enter vault description (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading vault description: %v\n", err))
		}
		if description != "" {
			descriptionToUpdate = &description
		}

		response, err := client.vaultClient.UpdateVault(ctx, &apiv1.UpdateVaultRequest{
			VaultId:     vaultID,
			Name:        nameToUpdate,
			Description: descriptionToUpdate,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error updating vault: %v\n", err))
		}

		printMessage("vault updated successfully:")
		printVaults([]*apiv1.Vault{response})
	},
}

var deleteVaultCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete vault",
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

		_, err = client.vaultClient.DeleteVault(ctx, &apiv1.DeleteVaultRequest{
			VaultId: vaultID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error deleting vault: %v\n", err))
		}

		printMessage("vault deleted successfully")
	},
}

var listVaultMembersCmd = &cobra.Command{
	Use:   "list-members",
	Short: "list vault members",
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

		response, err := client.vaultClient.ListVaultMembers(ctx, &apiv1.ListVaultMembersRequest{
			VaultId: vaultID,
			Limit:   100,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error listing vault members: %v\n", err))
		}

		printMessage("vault members:")
		printUsers(response.Users)
	},
}

func getVaultKey(ctx context.Context, client *client, vaultID string, privateKeyStr string) ([]byte, error) {
	response, err := client.vaultClient.GetVaultKeyProtected(ctx, &apiv1.GetVaultKeyProtectedRequest{
		VaultId: vaultID,
	})
	if err != nil {
		printFatalMessage(fmt.Sprintf("error getting vault key protected: %v\n", err))
	}

	privateKey, err := unmarshalPrivateKey([]byte(privateKeyStr))
	if err != nil {
		printFatalMessage(fmt.Sprintf("error unmarshalling private key: %v\n", err))
	}

	vaultKey, err := rsaDecrypt(privateKey, response.VaultKeyProtected)
	if err != nil {
		printFatalMessage(fmt.Sprintf("error decrypting vault key: %v\n", err))
	}

	return vaultKey, nil
}

var addVaultMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "add vault member",
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

		userID, err := askUser("Enter user id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading user id: %v\n", err))
		}

		userToAdd, err := client.userClient.GetUser(ctx, &apiv1.GetUserRequest{
			UserId: &userID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting user: %v\n", err))
		}

		vaultKey, err := getVaultKey(ctx, client, vaultID, config.PrivateKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting vault key: %v\n", err))
		}

		publicKey, err := unmarshalPublicKey(userToAdd.PublicKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error unmarshalling public key: %v\n", err))
		}

		vaultKeyProtected, err := rsaEncrypt(publicKey, vaultKey)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error encrypting vault key: %v\n", err))
		}

		_, err = client.vaultClient.AddMember(ctx, &apiv1.AddMemberRequest{
			VaultId:           vaultID,
			UserId:            userID,
			VaultKeyProtected: vaultKeyProtected,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error adding vault member: %v\n", err))
		}

		printMessage("vault member added successfully")
	},
}

var removeVaultMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "remove vault member",
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

		userID, err := askUser("Enter user id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading user id: %v\n", err))
		}

		_, err = client.vaultClient.RemoveMember(ctx, &apiv1.RemoveMemberRequest{
			VaultId: vaultID,
			UserId:  userID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error removing vault member: %v\n", err))
		}

		printMessage("vault member removed successfully")
	},
}
