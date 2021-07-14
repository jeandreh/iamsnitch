package cmd

import (
	"fmt"
	"log"

	"github.com/jeandreh/iam-snitch/iamsnitch"
	"github.com/jeandreh/iam-snitch/internal/aws"
	"github.com/jeandreh/iam-snitch/internal/cache"
	"github.com/jeandreh/iam-snitch/internal/domain"
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
	action   string
	resource string
)

func init() {
	whoCanCmd.Flags().StringVarP(&action, "action", "a", "", "action of interest")
	whoCanCmd.Flags().StringVarP(&resource, "resource", "r", "", "resource of interest")
	whoCanCmd.MarkFlagRequired("action")
	whoCanCmd.MarkFlagRequired("resource")

	rootCmd.AddCommand(whoCanCmd)
}

func runWhoCan(cmd *cobra.Command, args []string) error {
	cache, err := cache.NewCache()
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
	a := domain.Action{ID: action}
	r := domain.Resource{ID: resource}
	acl, err := accessService.WhoCan(a, r)
	if err != nil {
		return err
	}
	printOutput(a, acl)
	return nil
}

func printOutput(action domain.Action, acl []domain.AccessControlRule) {
	for _, r := range acl {
		log.Println(r.Principal.ID)
		p := getPermission(action, r.Permissions)
		log.Println("via: ")
		tabs := "  "
		for _, g := range p.GrantChain {
			log.Printf("%v|-> %v", tabs, g.String())
			tabs += "  "
		}
		fmt.Println("")
	}
}

// TODO: this shouldn't be necessary
func getPermission(action domain.Action, perms []domain.Permission) *domain.Permission {
	for _, p := range perms {
		if action == p.Action {
			return &p
		}
	}
	return nil
}
