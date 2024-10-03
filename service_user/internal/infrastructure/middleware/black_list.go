package middleware

type Blacklist struct {
	tokens map[string]bool
}

func NewBlacklist() *Blacklist {
	return &Blacklist{
		tokens: make(map[string]bool),
	}
}

func (b *Blacklist) AddToken(token string) {
	b.tokens[token] = true
}

func (b *Blacklist) IsTokenBlacklisted(token string) bool {
	return b.tokens[token]
}
