package util

import (
	"encoding/binary"
	"fmt"

	"github.com/wojciech-malota-wojcik/legacy/config"
	"golang.org/x/crypto/argon2"
)

// BuildPrivateKey builds private key from seed
func BuildPrivateKey(seed []byte) []byte {
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
	fmt.Printf("Computing encryption key, will take some time...\nProgress: %d%%\n", progress)
	for i := 0; i < config.SeedToKeySteps; i++ {
		binary.LittleEndian.PutUint64(preSalt, uint64(i))
		salt = argon2.Key(salt, preSalt, 2, 16*1024, 1, uint32(len(salt)))
		seed = argon2.Key(seed, salt, 3, 64*1024, 3, uint32(len(seed)))
		newProgress := 100 * (i + 1) / config.SeedToKeySteps
		if newProgress != progress {
			progress = newProgress
			fmt.Printf("Decryption key generation progress: %d%%\n", progress)
		}
	}
	return argon2.Key(seed, []byte("some very very random bytes for salt"), 5, 128*1024, 4, config.AESKeySize)
}
