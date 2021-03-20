package types

import "fmt"

type Successor struct {
	PublicKey []byte
	Key       []byte
	IV        []byte
	Part      []byte
}

func (s Successor) String() string {
	return fmt.Sprintf("%#v", s)
}

type SeedNode struct {
	Data []byte           `json:"d,omitempty"`
	Sub  map[int]SeedNode `json:"s,omitempty"`
}
