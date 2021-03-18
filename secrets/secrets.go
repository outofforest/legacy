package secrets

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"sort"

	"github.com/wojciech-malota-wojcik/legacy/config"
	"golang.org/x/crypto/argon2"
)

type SeedNode struct {
	Data []byte           `json:"d,omitempty"`
	Sub  map[int]SeedNode `json:"s,omitempty"`
}

type SharedSecret struct {
	PublicKey []byte
	Seed      SeedNode
}

func Generate() error {
	seed := make([]byte, config.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	secret := SharedSecret{Seed: SeedNode{Data: seed}}

	buildSeedTree(&secret.Seed, map[int]bool{})
	for i := range config.Successors {
		var sTree SeedNode
		successorTree(&secret.Seed, &sTree, i)
		rawTree, err := json.Marshal(sTree)
		if err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile(fmt.Sprintf("./%d.json", i), rawTree, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func Integrate() error {
	var masterTree SeedNode
	for i := range config.Successors {
		raw, err := ioutil.ReadFile(fmt.Sprintf("./%d.json", i))
		if err != nil {
			return err
		}
		var sTree SeedNode
		if err := json.Unmarshal(raw, &sTree); err != nil {
			return err
		}
		integrate(&masterTree, &sTree)
		fill(&masterTree, map[int]bool{})
		pr := progress(&masterTree)
		fmt.Printf("Progress: %d%%, Missing bytes: %d\n", int(math.Round(100.*float64(pr)/float64(config.SeedSize))), config.SeedSize-pr)
		if pr == config.SeedSize {
			break
		}
	}
	if masterTree.Data == nil {
		return errors.New("not enough YubiKeys to decrypt data")
	}
	keySeed := argon2.Key(masterTree.Data, []byte("some very very random bytes for salt"), 5, 128*1024, 4, ed25519.SeedSize)
	privKey := ed25519.NewKeyFromSeed(keySeed)
	fmt.Printf("%#v\n", []byte(privKey))
	return nil
}

func buildSeedTree(node *SeedNode, stack map[int]bool) {
	numOfBuckets := len(config.Successors) - len(stack)
	if numOfBuckets < config.RequiredToDecrypt {
		return
	}
	node.Sub = map[int]SeedNode{}
	buckets := equalDiv(node.Data, numOfBuckets)
	bI := 0
	for i := range config.Successors {
		if stack[i] {
			continue
		}
		if len(buckets[bI]) == 0 {
			return
		}
		stack[i] = true
		subNode := SeedNode{Data: buckets[bI]}
		buildSeedTree(&subNode, stack)
		node.Sub[i] = subNode
		bI += 1
		delete(stack, i)
	}
}

func equalDiv(data []byte, numOfBuckets int) [][]byte {
	buckets := make([][]byte, numOfBuckets)
	for i, v := range data {
		// this will spread bytes of each seed across buckets
		bucket := i % numOfBuckets
		buckets[bucket] = append(buckets[bucket], v)
	}
	return buckets
}

func successorTree(masterNode *SeedNode, successorNode *SeedNode, successorIndex int) {
	if masterNode.Sub == nil {
		return
	}
	successorNode.Sub = map[int]SeedNode{}
	for i, mN := range masterNode.Sub {
		if i == successorIndex {
			successorNode.Sub[i] = SeedNode{Data: mN.Data}
		} else {
			var node SeedNode
			successorTree(&mN, &node, successorIndex)
			if node.Sub != nil {
				successorNode.Sub[i] = node
			}
		}
	}
}

func integrate(masterNode *SeedNode, successorNode *SeedNode) {
	if successorNode.Data != nil {
		masterNode.Data = successorNode.Data
		return
	}
	if masterNode.Sub == nil {
		masterNode.Sub = map[int]SeedNode{}
	}
	for i, sN := range successorNode.Sub {
		node, ok := masterNode.Sub[i]
		if !ok {
			node = SeedNode{}
		}
		integrate(&node, &sN)
		masterNode.Sub[i] = node
	}
}

func fill(masterNode *SeedNode, stack map[int]bool) {
	if masterNode.Data != nil {
		return
	}
	expectedChildren := len(config.Successors) - len(stack)
	if len(masterNode.Sub) < expectedChildren {
		return
	}
	keys := make([]int, 0, expectedChildren)
	for k := range masterNode.Sub {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var data []byte
	for _, k := range keys {
		stack[k] = true
		node := masterNode.Sub[k]
		fill(&node, stack)
		delete(stack, k)
		if node.Data == nil {
			return
		}
		masterNode.Sub[k] = node
		data = append(data, node.Data...)
	}
	masterNode.Data = data
}

func progress(masterNode *SeedNode) int {
	if masterNode.Data != nil {
		return len(masterNode.Data)
	}
	var res int
	for _, sN := range masterNode.Sub {
		res += progress(&sN)
	}
	return res
}
