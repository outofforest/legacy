package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"sort"

	"github.com/wojciech-malota-wojcik/legacy/config"
	"github.com/wojciech-malota-wojcik/legacy/parts"
	"github.com/wojciech-malota-wojcik/legacy/types"
	"github.com/wojciech-malota-wojcik/legacy/util"
	"github.com/wojciech-malota-wojcik/legacy/yubi"
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
	key := util.BuildPrivateKey(masterTree.Data)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	rawData := make([]byte, len(parts.Data.Data))

	stream := cipher.NewCFBDecrypter(block, parts.Data.IV)
	stream.XORKeyStream(rawData, parts.Data.Data)

	return ioutil.WriteFile("./data.img", rawData, 0o444)
}

func integratePart(masterNode *types.SeedNode, successorNode *types.SeedNode) {
	if masterNode.Data != nil {
		return
	}
	if successorNode.Data != nil {
		masterNode.Data = successorNode.Data
		masterNode.Sub = nil
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
	dLen := 0
	for _, k := range keys {
		dLen += len(masterNode.Sub[k].Data)
	}
	masterNode.Data = make([]byte, 0, dLen)
	for i := 0; i < dLen; i++ {
		j := i / expectedChildren
		k := i % expectedChildren
		masterNode.Data = append(masterNode.Data, masterNode.Sub[keys[k]].Data[j])
	}
	masterNode.Sub = nil
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
