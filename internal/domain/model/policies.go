package model

// IdentityPolicy represents an identity-based policy attached to a principal.
// This includes managed and inline policies for IAM users, roles, and groups.
type IdentityPolicy struct {
	Principal  string
	Statements interface{} // []Statement from AWS, but we avoid importing aws here
}

// BoundaryPolicy represents a permission boundary attached to a principal.
// A permission boundary defines the maximum permissions a principal can have
// (acts as an intersection with identity policies).
type BoundaryPolicy struct {
	Name       string
	Arn        string
	Statements interface{} // []Statement from AWS, but we avoid importing aws here
}

// SCPPolicy represents a Service Control Policy at account or organizational unit level.
// SCPs explicitly deny actions, reducing the effective permissions available at account level.
type SCPPolicy struct {
	Arn        string
	Name       string
	Statements interface{} // []Statement from AWS, but we avoid importing aws here
	Scope      string      // FULL_AWS_ACCOUNT, OU, ACCOUNT
	TargetId   string      // Account ID or OU ID
}

// ResourcePolicy represents a resource-based policy that grants access to external principals.
// Resources like S3 buckets, SQS queues, etc. can have policies allowing cross-account access.
type ResourcePolicy struct {
	Service     string      // s3, sqs, sns, kms, secretsmanager, lambda
	ResourceArn string      // ARN of the resource
	Statements  interface{} // []Statement from AWS, but we avoid importing aws here
}
