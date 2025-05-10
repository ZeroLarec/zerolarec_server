package main

import (
	"context"
	"fmt"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(healthCmd)
	healthCmd.AddCommand(healthCheckCmd)
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "health information of the Zerolarec server",
}

var healthCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check the health of the Zerolarec server",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		config, err := loadConfig()
		if err != nil {
			printFatalMessage(fmt.Sprintf("error loading config: %s", err.Error()))
		}

		client, err := newClient(config.ApiEndpoint)
		if err != nil {
			printFatalMessage(fmt.Sprintf("error creating client: %v\n", err))
		}

		printMessage("checking health...")
		_, err = client.healthClient.Check(ctx, &apiv1.CheckRequest{})
		if err != nil {
			printFatalMessage(fmt.Sprintf("error checking health: %v\n", err))
		}

		printMessage("service is healthy")
	},
}
