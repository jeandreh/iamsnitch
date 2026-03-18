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
	# find out which principals can perform any of the Put operation on any of 
	# the S3 buckets in your account (returns PutObject, PutObjectACL, etc.)
	iamsnitch whocan -p "s3:Put*" -r "*"

	# find out which principals are allowed to perform "s3:*" on every S3 bucket
	# (ignores wildcard *, returning only entries containing "s3:*" and "*")
	iamsnitch whocan -e -p "s3:*" "*"`,
		RunE: runWhoCan,
	}
	permissions []string
	resources   []string
	exact       bool
)

func init() {
	whoCanCmd.Flags().BoolVarP(&exact, "exact", "e", false, "whether to use an exact match or interpret * as wildcard")
	whoCanCmd.Flags().StringSliceVarP(&permissions, "permissions", "p", []string{}, "actions of interest")
	whoCanCmd.Flags().StringSliceVarP(&resources, "resources", "r", []string{}, "resource of interest")
	whoCanCmd.MarkFlagRequired("permissions")
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

	acl, err := accessService.WhoCan(permissions, resources, exact)
	if err != nil {
		return err
	}
	printOutput(acl)
	return nil
}

func printOutput(acl []model.AccessControlRule) {
	if len(acl) == 0 {
		fmt.Println("No matching access control rules found.")
		return
	}

	fmt.Printf("Found %d matching access control rules:\n\n", len(acl))

	for i, r := range acl {
		fmt.Printf("─── Rule %d ──────────────────────────────────────────────────────────────\n", i+1)
		fmt.Printf("Principal:  %s\n", r.Principal.ID)
		fmt.Printf("Permission: %s\n", r.Permission.ID)
		fmt.Printf("Resource:   %s\n", r.Resource.ID)

		if len(r.UncheckedConditions) > 0 {
			fmt.Println("Unchecked Conditions:")
			for _, c := range r.UncheckedConditions {
				fmt.Printf("  • %s %s %v\n", c.Operator, c.Key, c.Value)
			}
		}

		fmt.Println("Grant Chain:")
		for j, g := range r.GrantChain {
			prefix := "  "
			if j > 0 {
				prefix = "    └── "
			} else {
				prefix = "  └── "
			}
			fmt.Printf("%s%s\n", prefix, g)
		}
		fmt.Println()
	}
}
