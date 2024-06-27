package precompiles

import (
	"bytes"

	enc "github.com/FairBlock/DistributedIBE/encryption"
	bls "github.com/drand/kyber-bls12381"
	"github.com/ethereum/go-ethereum/precompile"
	"github.com/ethereum/go-ethereum/precompile/abi"
)

type Decryption struct {
	precompile.StatefulPrecompiledContract
}
func NewDecryption() *Decryption {
	return &Decryption{
		StatefulPrecompiledContract: precompile.NewStatefulPrecompiledContract(
			abi.StringsABI,
		),
	}
}

func (con Decryption) Decrypt(ctx precompile.StatefulContext, privateKeyByte []byte, cipherBytes []byte) ([]byte, error) {
	suite := bls.NewBLS12381Suite()
	privateKeyPoint := suite.G2().Point()
	err := privateKeyPoint.UnmarshalBinary(privateKeyByte)
	if err != nil {
		return []byte{},err
	}
	var destPlainText bytes.Buffer
	var cipherBuffer bytes.Buffer
	_, err = cipherBuffer.Write(cipherBytes)
	if err != nil {
		return []byte{},err
	}
	err = enc.Decrypt(privateKeyPoint, privateKeyPoint, &destPlainText, &cipherBuffer)
	if err != nil {
		return []byte{},err
	}
	return []byte(destPlainText.String()),nil
}
