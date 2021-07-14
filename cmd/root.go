package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "iamsnitch",
		Short: "Dive deep into your IAM permissions",
		Long:  `IAM Snitch helps you answer one simple question: who can do what in your AWS account`,
	}
)

func Execute() error {
	return rootCmd.Execute()
}
