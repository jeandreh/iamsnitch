package aws

type PageToken struct {
	token *string
}

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
