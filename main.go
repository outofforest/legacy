package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"sort"

	"github.com/wojciech-malota-wojcik/legacy/config"
	"github.com/wojciech-malota-wojcik/legacy/parts"
	"github.com/wojciech-malota-wojcik/legacy/types"
	"github.com/wojciech-malota-wojcik/legacy/util"
	"github.com/wojciech-malota-wojcik/legacy/yubi"
	"golang.org/x/crypto/argon2"
)

func main() {
	util.WorkingDir(0)
	if err := integrate(); err != nil {
		log.Fatal(err)
	}
}

func integrate() error {
	var masterTree types.SeedNode
	for _, s := range parts.Successors {
		// decrypt symmetric key using YubiKey of successor

		partKey, err := yubi.Decrypt(s.Key)
		if err != nil {
			return err
		}

		// decrypt part file using symmetric key

		block, err := aes.NewCipher(partKey)
		if err != nil {
			return err
		}

		rawTree := make([]byte, len(s.Part))

		stream := cipher.NewCFBDecrypter(block, s.IV)
		stream.XORKeyStream(rawTree, s.Part)

		var sTree types.SeedNode
		if err := json.Unmarshal(rawTree, &sTree); err != nil {
			return err
		}
		integratePart(&masterTree, &sTree)
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
	buildPrivateKey(masterTree.Data)
	return nil
}

func integratePart(masterNode *types.SeedNode, successorNode *types.SeedNode) {
	if masterNode.Data != nil {
		return
	}
	if successorNode.Data != nil {
		masterNode.Data = successorNode.Data
		return
	}
	if masterNode.Sub == nil {
		masterNode.Sub = map[int]types.SeedNode{}
	}
	for i, sN := range successorNode.Sub {
		node, ok := masterNode.Sub[i]
		if !ok {
			node = types.SeedNode{}
		}
		integratePart(&node, &sN)
		masterNode.Sub[i] = node
	}
}

func fill(masterNode *types.SeedNode, stack map[int]bool) {
	if masterNode.Data != nil {
		masterNode.Sub = nil
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

func progress(masterNode *types.SeedNode) int {
	if masterNode.Data != nil {
		return len(masterNode.Data)
	}
	var res int
	for _, sN := range masterNode.Sub {
		res += progress(&sN)
	}
	return res
}

func buildPrivateKey(seed []byte) {
	preSalt := make([]byte, 8)
	salt := []byte{
		seed[0],
		seed[len(seed)-1],
		seed[len(seed)/2],
		seed[len(seed)/3],
		seed[2*len(seed)/3],
		seed[len(seed)/4],
		seed[3*len(seed)/4],
		seed[3*len(seed)/5],
	}
	progress := 0
	fmt.Printf("Progress: %d%%\n", progress)
	for i := 0; i < config.SeedToKeySteps; i++ {
		binary.LittleEndian.PutUint64(preSalt, uint64(i))
		salt = argon2.Key(salt, preSalt, 2, 16*1024, 1, uint32(len(salt)))
		seed = argon2.Key(seed, salt, 3, 64*1024, 3, uint32(len(seed)))
		newProgress := 100 * (i + 1) / config.SeedToKeySteps
		if newProgress != progress {
			progress = newProgress
			fmt.Printf("Progress: %d%%\n", progress)
		}
	}
	key := argon2.Key(seed, []byte("some very very random bytes for salt"), 5, 128*1024, 4, config.AESKeySize)
	fmt.Printf("%#v\n", []byte(key))
}
