package cmd

import (
	"github.com/jeandreh/iam-snitch/iamsnitch"
	"github.com/jeandreh/iam-snitch/internal/aws"
	"github.com/jeandreh/iam-snitch/internal/cache"
	"github.com/spf13/cobra"
)

var (
	resourceServices []string
	refreshCmd       = &cobra.Command{
		Use:   "refresh",
		Short: "Refresh access control list from cloud provider",
		RunE:  runRefreshCmd,
	}
)

func init() {
	refreshCmd.Flags().StringSliceVar(&resourceServices, "resource-policies", []string{}, "Comma-separated list of services to include resource policies for (s3,sqs,kms,lambda,secretsmanager)")
	rootCmd.AddCommand(refreshCmd)
}

func runRefreshCmd(cmd *cobra.Command, args []string) error {
	cache, err := cache.New()
	if err != nil {
		return err
	}

	provider, err := aws.NewIAMProvider(nil)
	if err != nil {
		return err
	}

	accessService := iamsnitch.NewAccessControlService(provider, cache)
	if err != nil {
		return err
	}

	if err := accessService.RefreshACL(resourceServices); err != nil {
		return err
	}
	return nil
}
