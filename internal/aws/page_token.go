package aws

import "github.com/jeandreh/iam-snitch/internal/domain/ports"

type PageToken struct {
	token *string
}

var _ ports.PageIface = (*PageToken)(nil)

func NewPageToken(token *string) *PageToken {
	return &PageToken{
		token: token,
	}
}

func (p *PageToken) Next() *string {
	return p.token
}

func (p *PageToken) HasNext() bool {
	return p.token != nil
}
