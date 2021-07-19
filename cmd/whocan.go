package cmd

import (
	"fmt"

	"github.com/jeandreh/iam-snitch/iamsnitch"
	"github.com/jeandreh/iam-snitch/internal/aws"
	"github.com/jeandreh/iam-snitch/internal/cache"
	"github.com/jeandreh/iam-snitch/internal/domain/model"
	"github.com/spf13/cobra"
)

var (
	whoCanCmd = &cobra.Command{
		Use:   "whocan",
		Short: "find out who can do what",
		Long: `Analyses your users, roles and policies to determine which of them attend to your search criteria:
Usage example:  
	# find out which principals can put objects on all the S3 buckets in your account
	iamsnitch whocan -a "s3:PutObject" -r "*"`,
		RunE: runWhoCan,
	}
	actions   []string
	resources []string
	exact     bool
)

func init() {
	whoCanCmd.Flags().BoolVarP(&exact, "exact", "e", false, "whether to use an exact match or interpret * as wildcard")
	whoCanCmd.Flags().StringSliceVarP(&actions, "actions", "a", []string{}, "actions of interest")
	whoCanCmd.Flags().StringSliceVarP(&resources, "resources", "r", []string{}, "resource of interest")
	whoCanCmd.MarkFlagRequired("actions")
	whoCanCmd.MarkFlagRequired("resources")

	rootCmd.AddCommand(whoCanCmd)
}

func runWhoCan(cmd *cobra.Command, args []string) error {
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

	var res []model.Resource
	for _, v := range resources {
		res = append(res, model.Resource{ID: v})
	}

	acl, err := accessService.WhoCan(actions, res, exact)
	if err != nil {
		return err
	}
	printOutput(acl)
	return nil
}

func printOutput(acl []model.AccessControlRule) {
	for _, r := range acl {
		fmt.Printf("principal: %s\n", r.Principal.ID)
		fmt.Printf("permission: %s\n", r.Permission.ID)
		fmt.Printf("resource: %s\n", r.Resource.ID)
		fmt.Println("via: ")

		tabs := " "
		for _, g := range r.GrantChain {
			fmt.Printf("%v|-> %v\n", tabs, g.String())
			tabs += " "
		}
		fmt.Println("")
	}
}
