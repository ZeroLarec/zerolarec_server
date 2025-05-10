package main

import (
	"context"
	"fmt"
	"time"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	rootCmd.AddCommand(accessRuleCmd)
	accessRuleCmd.AddCommand(getAccessRuleCmd)
	accessRuleCmd.AddCommand(createAccessRuleCmd)
	accessRuleCmd.AddCommand(listAccessRulesCmd)
	accessRuleCmd.AddCommand(updateAccessRuleCmd)
	accessRuleCmd.AddCommand(deleteAccessRuleCmd)
}

var accessRuleCmd = &cobra.Command{
	Use:   "access-rule",
	Short: "access rule",
}

func printAccessRules(accessRules []*apiv1.AccessRule) {
	printMessage("--------------------------------")
	for _, accessRule := range accessRules {
		printMessage(fmt.Sprintf("Access rule id: %s", accessRule.AccessRuleId))
		printMessage(fmt.Sprintf("User-id: %s", accessRule.UserId))
		printMessage(fmt.Sprintf("Vault-id: %s", accessRule.VaultId))
		printMessage(fmt.Sprintf("Secret-id: %s", accessRule.SecretId))
		printMessage(fmt.Sprintf("Description: %s", accessRule.Description))
		printMessage("Permissions:")
		for _, permission := range accessRule.Permissions {
			printMessage(fmt.Sprintf("  - %s", permission.String()))
		}
		printMessage("--------------------------------")
	}
}

func roleToPermissions(role string) ([]apiv1.Permission, error) {
	var permissions []apiv1.Permission

	switch role {
	case "viewer":
		permissions = []apiv1.Permission{
			apiv1.Permission_SECRET_GET,
		}
	case "editor":
		permissions = []apiv1.Permission{
			apiv1.Permission_SECRET_GET,
			apiv1.Permission_SECRET_CREATE,
			apiv1.Permission_SECRET_UPDATE,
			apiv1.Permission_SECRET_DELETE,

			apiv1.Permission_VAULT_UPDATE,
			apiv1.Permission_VAULT_DELETE,
		}
	case "admin":
		permissions = []apiv1.Permission{
			apiv1.Permission_SECRET_GET,
			apiv1.Permission_SECRET_CREATE,
			apiv1.Permission_SECRET_UPDATE,
			apiv1.Permission_SECRET_DELETE,
			apiv1.Permission_SECRET_GRANT_ACCESS,

			apiv1.Permission_VAULT_UPDATE,
			apiv1.Permission_VAULT_DELETE,
			apiv1.Permission_VAULT_MANAGE_MEMBERS,
			apiv1.Permission_VAULT_GRANT_ACCESS,
		}
	default:
		return nil, fmt.Errorf("invalid role: %s", role)
	}
	return permissions, nil
}

var listAccessRulesCmd = &cobra.Command{
	Use:   "list",
	Short: "list access rules",
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

		accessRules, err := client.accessRuleClient.ListAccessRules(ctx, &apiv1.ListAccessRulesRequest{
			VaultId: vaultID,
			Limit:   100,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error listing access rules: %v\n", err))
		}

		printAccessRules(accessRules.AccessRules)
	},
}

var getAccessRuleCmd = &cobra.Command{
	Use:   "get",
	Short: "get access rule",
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

		accessRuleID, err := askUser("Enter access rule id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading access rule id: %v\n", err))
		}

		accessRule, err := client.accessRuleClient.GetAccessRule(ctx, &apiv1.GetAccessRuleRequest{
			AccessRuleId: accessRuleID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting access rule: %v\n", err))
		}

		printAccessRules([]*apiv1.AccessRule{accessRule})

	},
}

var createAccessRuleCmd = &cobra.Command{
	Use:   "create",
	Short: "create access rule",
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

		secretID, err := askUser("Enter secret id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading secret id: %v\n", err))
		}

		description, err := askUser("Enter description (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading description: %v\n", err))
		}

		role, err := askUser("Enter role: [viewer, editor, admin]")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading role: %v\n", err))
		}

		permissions, err := roleToPermissions(role)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error converting role to permissions: %v\n", err))
		}

		ttl, err := askUser("Enter ttl")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading ttl: %v\n", err))
		}
		ttlDuration, err := time.ParseDuration(ttl)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error parsing ttl: %v\n", err))
		}
		expiresAt := time.Now().Add(ttlDuration)

		_, err = client.accessRuleClient.CreateAccessRule(ctx, &apiv1.CreateAccessRuleRequest{
			UserId:      userID,
			VaultId:     vaultID,
			SecretId:    secretID,
			Description: description,
			Permissions: permissions,
			ExpiresAt:   timestamppb.New(expiresAt),
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating access rule: %v\n", err))
		}

		printMessage("Access rule created successfully")
	},
}

var updateAccessRuleCmd = &cobra.Command{
	Use:   "update",
	Short: "update access rule",
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

		accessRuleID, err := askUser("Enter access rule id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading access rule id: %v\n", err))
		}
		req := &apiv1.UpdateAccessRuleRequest{
			AccessRuleId: accessRuleID,
		}

		description, err := askUser("Enter description (optional)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading description: %v\n", err))
		}
		if description != "" {
			req.Description = &description
		}

		role, err := askUser("Enter role: [viewer, editor, admin] (leave empty to keep current role)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading role: %v\n", err))
		}
		permissions, err := roleToPermissions(role)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error converting role to permissions: %v\n", err))
		}
		req.Permissions = &apiv1.UpdateAccessRuleRequest_UpdatedPermissions{
			Permissions: permissions,
		}

		ttl, err := askUser("Enter ttl (leave empty to keep current ttl)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading ttl: %v\n", err))
		}
		if ttl != "" {
			ttlDuration, err := time.ParseDuration(ttl)
			if err != nil {
				printFatalMessage(fmt.Sprintf("error parsing ttl: %v\n", err))
			}
			req.ExpiresAt = timestamppb.New(time.Now().Add(ttlDuration))
		}

		_, err = client.accessRuleClient.UpdateAccessRule(ctx, req)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error updating access rule: %v\n", err))
		}

		printMessage("Access rule updated successfully")
	},
}

var deleteAccessRuleCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete access rule",
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

		accessRuleID, err := askUser("Enter access rule id")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading access rule id: %v\n", err))
		}

		_, err = client.accessRuleClient.DeleteAccessRule(ctx, &apiv1.DeleteAccessRuleRequest{
			AccessRuleId: accessRuleID,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error deleting access rule: %v\n", err))
		}

		printMessage("Access rule deleted successfully")
	},
}
