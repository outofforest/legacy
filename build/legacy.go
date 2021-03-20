package build

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/wojciech-malota-wojcik/build"
	"github.com/wojciech-malota-wojcik/legacy/config"
	"github.com/wojciech-malota-wojcik/legacy/types"
	"html/template"
	"io/ioutil"
	"math"
	"os"
)

func generateLegacy() error {
	knownParts()

	seed := make([]byte, config.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	masterTree := types.SeedNode{Data: seed}
	buildSeedTree(&masterTree, map[int]bool{})
	if err := os.Mkdir("./parts", 0o755); err != nil && !os.IsExist(err) {
		return err
	}

	ss := make([]int, 0, len(config.Successors))
	for i, s := range config.Successors {
		var sTree types.SeedNode
		successorTree(&masterTree, &sTree, i)
		rawTree, err := json.Marshal(sTree)
		if err != nil {
			panic(err)
		}

		// encrypt part file using symmetric key

		partKey := make([]byte, config.AESKeySize)
		if _, err := rand.Read(partKey); err != nil {
			return err
		}
		block, err := aes.NewCipher(partKey)
		if err != nil {
			return err
		}

		sInfo := types.Successor{
			PublicKey: s,
			IV:        make([]byte, block.BlockSize()),
			Part:      make([]byte, len(rawTree)),
		}

		if _, err := rand.Read(sInfo.IV); err != nil {
			return err
		}
		stream := cipher.NewCFBEncrypter(block, sInfo.IV)
		stream.XORKeyStream(sInfo.Part, rawTree)

		// encrypt symmetric key using public key of successor

		pubKey, err := x509.ParsePKCS1PublicKey(s)
		if err != nil {
			return err
		}
		sInfo.Key, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, partKey)
		if err != nil {
			return err
		}

		buf := &bytes.Buffer{}
		if err := sTplSuccessor.Execute(buf, successorEntry{Index: i, Data: sInfo}); err != nil {
			return err
		}
		if err := ioutil.WriteFile(fmt.Sprintf("./parts/s%d.go", i), buf.Bytes(), 0o444); err != nil {
			return err
		}
		ss = append(ss, i)
	}
	buf := &bytes.Buffer{}
	if err := sTpl.Execute(buf, ss); err != nil {
		return err
	}
	if err := ioutil.WriteFile("./parts/parts.go", buf.Bytes(), 0o444); err != nil {
		return err
	}
	return nil
}

func buildLegacy(ctx context.Context, deps build.DepsFunc) error {
	deps(generateLegacy)
	return goBuildPkg(ctx, ".", "bin/legacy-bin")
}

const tpl = `package parts

import "github.com/wojciech-malota-wojcik/legacy/types"

var Successors = []types.Successor{
	{{- range $val := . }}
    successor{{ $val }},{{ end }}
}
`

const tplSuccessor = `package parts

import "github.com/wojciech-malota-wojcik/legacy/types"

var successor{{ .Index }} = {{ .Data }}
`

var sTpl = template.Must(template.New("").Parse(tpl))
var sTplSuccessor = template.Must(template.New("").Parse(tplSuccessor))

type successorEntry struct {
	Index int
	Data  types.Successor
}

func knownParts() {
	leafLen := 1
	for i := len(config.Successors); i >= config.RequiredToDecrypt; i-- {
		leafLen *= i
	}
	bytesInLeaf := int(math.Floor(float64(config.SeedSize) / float64(leafLen)))
	fmt.Printf("Bytes in leaf: %d\n", bytesInLeaf)
	if bytesInLeaf < 5 {
		panic("minimum required bytes per leaf is 5, use longer seed")
	}
	sLen := len(config.Successors)
	for i := 1; i <= config.RequiredToDecrypt; i++ {
		known := 0.
		for j := sLen; j >= config.RequiredToDecrypt; j-- {
			known += (1. - known) * float64(i) / float64(j)
		}
		missingBytes := int(math.Floor((1. - known) * float64(config.SeedSize)))
		fmt.Printf("Knowledge owned by %d successor(s): %d%%, Missing bytes: %d\n", i, int(math.Round(100.*known)), missingBytes)
	}
}

func buildSeedTree(node *types.SeedNode, stack map[int]bool) {
	numOfBuckets := len(config.Successors) - len(stack)
	if numOfBuckets < config.RequiredToDecrypt {
		return
	}
	node.Sub = map[int]types.SeedNode{}
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
		subNode := types.SeedNode{Data: buckets[bI]}
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

func successorTree(masterNode *types.SeedNode, successorNode *types.SeedNode, successorIndex int) {
	if masterNode.Sub == nil {
		return
	}
	successorNode.Sub = map[int]types.SeedNode{}
	for i, mN := range masterNode.Sub {
		if i == successorIndex {
			successorNode.Sub[i] = types.SeedNode{Data: mN.Data}
		} else {
			var node types.SeedNode
			successorTree(&mN, &node, successorIndex)
			if node.Sub != nil {
				successorNode.Sub[i] = node
			}
		}
	}
}
