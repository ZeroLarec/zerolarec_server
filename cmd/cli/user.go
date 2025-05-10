package main

import (
	"context"
	"fmt"
	"os"
	"time"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/spf13/cobra"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "user management",
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(getUserCmd)
	userCmd.AddCommand(updateUserCmd)
	userCmd.AddCommand(deleteUserCmd)
}

func printUsers(users []*apiv1.User) {
	printMessage("------------------------------------------------")
	for _, user := range users {
		printMessage(fmt.Sprintf("|user-id:  | %s", user.UserId))
		printMessage(fmt.Sprintf("|login:    | %s", user.Login))
		printMessage(fmt.Sprintf("|created-at| %s", user.CreatedAt.AsTime().Format(time.RFC1123)))
		printMessage(fmt.Sprintf("|updated-at| %s", user.UpdatedAt.AsTime().Format(time.RFC1123)))
		printMessage("------------------------------------------------")
	}
}

var getUserCmd = &cobra.Command{
	Use:   "get",
	Short: "get user",
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

		var userIDToGet *string
		userId, err := askUser("Enter user id (default: current user)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading user id: %v\n", err))
		}
		if userId != "" {
			userIDToGet = &userId
		}

		response, err := client.userClient.GetUser(ctx, &apiv1.GetUserRequest{
			UserId: userIDToGet,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error getting user: %v\n", err))
		}

		fmt.Println("got user:")
		printUsers([]*apiv1.User{response})
	},
}

var updateUserCmd = &cobra.Command{
	Use:   "update",
	Short: "update user",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			fmt.Printf("error loading config: %v\n", err)
			os.Exit(1)
		}

		ctx, client, err := newLoggedClient(ctx, config.ApiEndpoint, config.Login, config.Password)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		var loginToUpdate *string
		login, err := askUser("Enter new login: (no update: just press enter)")
		if err != nil {
			printFatalMessage(fmt.Sprintf("error reading login: %v\n", err))
		}

		if login != "" {
			loginToUpdate = &login
			config.Login = login
		}

		response, err := client.userClient.UpdateUser(ctx, &apiv1.UpdateUserRequest{
			Login: loginToUpdate,
		})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error updating user: %v\n", err))
		}

		fmt.Println("user updated successfully:")

		err = saveConfig(config)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error saving config: %v\n", err))
		}

		printMessage("config saved successfully")

		printUsers([]*apiv1.User{response})
	},
}

var deleteUserCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete user",
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

		_, err = client.userClient.DeleteUser(ctx, &apiv1.DeleteUserRequest{})
		if err != nil {
			printFatalMessage(fmt.Sprintf("failed to delete user: %v", err))
		}

		fmt.Println("user deleted successfully")
	},
}
