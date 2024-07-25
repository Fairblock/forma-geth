package precompiles

import (
	"bytes"

	enc "github.com/FairBlock/DistributedIBE/encryption"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/ethereum/go-ethereum/precompile"
	"github.com/ethereum/go-ethereum/precompile/abi"
)

type Decryption struct {
	precompile.StatefulPrecompiledContract
	pk []byte
}
func NewDecryption() *Decryption {
	return &Decryption{
		StatefulPrecompiledContract: precompile.NewStatefulPrecompiledContract(
			abi.DecryptionABI,
		),
		pk: []byte{},
	}
}
func (con *Decryption) GetPK(ctx precompile.StatefulContext) ([]byte,error){
	return con.pk,nil;
}
func (con *Decryption) SetPK(ctx precompile.StatefulContext, _pk []byte) (bool,error) {
	suite := bls.NewBLS12381Suite()
	pkPoint := suite.G1().Point()
	err := pkPoint.UnmarshalBinary(_pk)
	if err != nil {
		return false,err;
	}
	con.pk = _pk;
	return true,nil;
}

func (con *Decryption) Decrypt(ctx precompile.StatefulContext, privateKeyByte []byte, cipherBytes []byte, id string) ([]byte, error) {
	suite := bls.NewBLS12381Suite()
	privateKeyPoint := suite.G2().Point()
	err := privateKeyPoint.UnmarshalBinary(privateKeyByte)
	if err != nil {
		return []byte{},err
	}
	pkPoint := suite.G1().Point()
	_ = pkPoint.UnmarshalBinary(con.pk)
	hG2, ok := suite.G2().Point().(kyber.HashablePoint)
	if !ok {
		panic("invalid point")
	}
	idByte := []byte(id)
	Qid := hG2.Hash(idByte)
	p1 := suite.Pair(pkPoint,Qid)
	p2 := suite.Pair(suite.G1().Point().Base(), privateKeyPoint)
	if !p1.Equal(p2){
		return []byte{},nil
	}
	var destPlainText bytes.Buffer
	var cipherBuffer bytes.Buffer
	_, err = cipherBuffer.Write(cipherBytes)
	if err != nil {
		return []byte{},err
	}
	err = enc.Decrypt(pkPoint, privateKeyPoint, &destPlainText, &cipherBuffer)
	if err != nil {
		return []byte{},err
	}
	return []byte(destPlainText.String()),nil
}
