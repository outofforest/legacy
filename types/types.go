package types

import "fmt"

// Successor contains all the data required to decrypt a part
type Successor struct {
	PublicKey []byte
	Key       []byte
	IV        []byte
	Part      []byte
}

// String returns string representation of data
func (s Successor) String() string {
	return fmt.Sprintf("%#v", s)
}

// Data represent data
type Data struct {
	IV   []byte
	Data []byte
}

// String returns string representation of data
func (d Data) String() string {
	return fmt.Sprintf("%#v", d)
}

// SeedNode is a node of seed tree
type SeedNode struct {
	Data []byte           `json:"d,omitempty"`
	Sub  map[int]SeedNode `json:"s,omitempty"`
}
