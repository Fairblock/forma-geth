package jsonutil

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/precompile"
	"github.com/ethereum/go-ethereum/precompile/bindings"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/valyala/fastjson"
)

type JsonUtil struct {
	precompile.StatefulPrecompiledContract
}

func NewJsonUtil() *JsonUtil {
	return &JsonUtil{
		StatefulPrecompiledContract: precompile.NewStatefulPrecompiledContract(
			bindings.JsonUtilABI,
		),
	}
}

// Solidity: function validate(string memory jsonBlob) view external returns (bool)
func (c *JsonUtil) Validate(ctx precompile.StatefulContext, jsonBlob string) (bool, error) {
	validationErr := fastjson.Validate(jsonBlob)
	if validationErr != nil {
		return false, errors.New("invalid JSON")
	}
	return true, nil
}

// Solidity: function exists(string jsonBlob, string path) view returns(bool)
func (c *JsonUtil) Exists(ctx precompile.StatefulContext, jsonBlob string, path string) (bool, error) {
	filteredVal, err := jsonGet(jsonBlob, path)
	if err != nil {
		return false, err
	}
	return filteredVal.Exists(), nil
}

// Solidity: function get(string jsonBlob, string path) view returns(string)
func (c *JsonUtil) Get(ctx precompile.StatefulContext, jsonBlob string, path string) (string, error) {
	filteredVal, err := jsonGet(jsonBlob, path)
	if err != nil {
		return "", err
	}
	return filteredVal.String(), nil
}

// Solidity: function getBool(string jsonBlob, string path) view returns(bool)
func (c *JsonUtil) GetBool(ctx precompile.StatefulContext, jsonBlob string, path string) (bool, error) {
	filteredVal, err := jsonGet(jsonBlob, path)
	if err != nil {
		return false, err
	}
	return filteredVal.Bool(), nil
}

// Solidity: function getInt(string jsonBlob, string path) view returns(int256)
func (c *JsonUtil) GetInt(ctx precompile.StatefulContext, jsonBlob string, path string) (*big.Int, error) {
	filteredVal, err := jsonGet(jsonBlob, path)
	if err != nil {
		return nil, err
	}
	bigIntVal, ok := new(big.Int).SetString(filteredVal.String(), 10)
	if !ok {
		return nil, errors.New("invalid int")
	}
	return bigIntVal, nil
}

// Solidity: function getUint(string jsonBlob, string path) view returns(uint256)
func (c *JsonUtil) GetUint(ctx precompile.StatefulContext, jsonBlob string, path string) (*big.Int, error) {
	return c.GetInt(ctx, jsonBlob, path)
}

// Solidity: function dataURI(string jsonBlob) view returns(string)
func (c *JsonUtil) DataURI(ctx precompile.StatefulContext, jsonBlob string) (string, error) {
	if err := fastjson.Validate(jsonBlob); err != nil {
		return "", errors.New("invalid JSON")
	}
	dataURI := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(jsonBlob))
	return dataURI, nil
}

// Solidity: function compact(string memory jsonBlob) view external returns (string memory)
func (c *JsonUtil) Compact(ctx precompile.StatefulContext, jsonBlob string) (string, error) {
	var buf bytes.Buffer
	err := json.Compact(&buf, []byte(jsonBlob))
	if err != nil {
		return "{}", errors.New("unknown compact error")
	}
	return buf.String(), nil
}

// Solidity: function set(string jsonBlob, string[] paths, string[] values) view returns(string)
func (c *JsonUtil) Set(ctx precompile.StatefulContext, jsonBlob string, paths []string, values []string) (string, error) {
	interfaceValues := make([]interface{}, len(values))
	for i, v := range values {
		interfaceValues[i] = v
	}
	return jsonSet(jsonBlob, paths, interfaceValues)
}

// Solidity: function set(string jsonBlob, string path, string value) view returns(string)
func (c *JsonUtil) Set0(ctx precompile.StatefulContext, jsonBlob string, path string, value string) (string, error) {
	return jsonSet(jsonBlob, []string{path}, []interface{}{value})
}

// Solidity: function setRaw(string jsonBlob, string path, string rawBlob) view returns(string)
func (c *JsonUtil) SetRaw(ctx precompile.StatefulContext, jsonBlob string, path string, rawBlob string) (string, error) {
	return jsonSetRaw(jsonBlob, []string{path}, []string{rawBlob})
}

// Solidity: function setRaw(string jsonBlob, string[] paths, string[] rawBlobs) view returns(string)
func (c *JsonUtil) SetRaw0(ctx precompile.StatefulContext, jsonBlob string, paths []string, rawBlobs []string) (string, error) {
	return jsonSetRaw(jsonBlob, paths, rawBlobs)
}

// Solidity: function setInt(string jsonBlob, string[] paths, int256[] values) view returns(string)
func (c *JsonUtil) SetInt(ctx precompile.StatefulContext, jsonBlob string, paths []string, values []*big.Int) (string, error) {
	interfaceValues := make([]interface{}, len(values))
	for i, v := range values {
		interfaceValues[i] = v
	}
	return jsonSet(jsonBlob, paths, interfaceValues)
}

// Solidity: function setInt(string jsonBlob, string path, int256 value) view returns(string)
func (c *JsonUtil) SetInt0(ctx precompile.StatefulContext, jsonBlob string, path string, value *big.Int) (string, error) {
	return jsonSet(jsonBlob, []string{path}, []interface{}{value})
}

// Solidity: function setUint(string jsonBlob, string[] paths, uint256[] values) view returns(string)
func (c *JsonUtil) SetUint(ctx precompile.StatefulContext, jsonBlob string, paths []string, values []*big.Int) (string, error) {
	return c.SetInt(ctx, jsonBlob, paths, values)
}

// Solidity: function setUint(string jsonBlob, string path, uint256 value) view returns(string)
func (c *JsonUtil) SetUint0(ctx precompile.StatefulContext, jsonBlob string, path string, value *big.Int) (string, error) {
	return c.SetInt0(ctx, jsonBlob, path, value)
}

// Solidity: function setBool(string jsonBlob, string[] paths, bool[] values) view returns(string)
func (c *JsonUtil) SetBool(ctx precompile.StatefulContext, jsonBlob string, paths []string, values []bool) (string, error) {
	interfaceValues := make([]interface{}, len(values))
	for i, v := range values {
		interfaceValues[i] = v
	}
	return jsonSet(jsonBlob, paths, interfaceValues)
}

// Solidity: function setBool(string jsonBlob, string path, bool value) view returns(string)
func (c *JsonUtil) SetBool0(ctx precompile.StatefulContext, jsonBlob string, path string, value bool) (string, error) {
	return jsonSet(jsonBlob, []string{path}, []interface{}{value})
}

// Solidity: function subReplace(string jsonBlob, string searchPath, string[] replacePaths, string[] values) view returns(string)
func (c *JsonUtil) SubReplace(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePaths []string, values []string) (string, error) {
	interfaceValues := make([]interface{}, len(values))
	for i, v := range values {
		interfaceValues[i] = v
	}
	return jsonSubReplace(jsonBlob, searchPath, replacePaths, interfaceValues)
}

// Solidity: function subReplace(string jsonBlob, string searchPath, string replacePath, string value) view returns(string)
func (c *JsonUtil) SubReplace0(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePath string, value string) (string, error) {
	return jsonSubReplace(jsonBlob, searchPath, []string{replacePath}, []interface{}{value})
}

// Solidity: function subReplaceBool(string jsonBlob, string searchPath, string[] replacePaths, bool[] values) view returns(string)
func (c *JsonUtil) SubReplaceBool(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePaths []string, values []bool) (string, error) {
	interfaceValues := make([]interface{}, len(values))
	for i, v := range values {
		interfaceValues[i] = v
	}
	return jsonSubReplace(jsonBlob, searchPath, replacePaths, interfaceValues)
}

// Solidity: function subReplaceBool(string jsonBlob, string searchPath, string replacePath, bool value) view returns(string)
func (c *JsonUtil) SubReplaceBool0(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePath string, value bool) (string, error) {
	return jsonSubReplace(jsonBlob, searchPath, []string{replacePath}, []interface{}{value})
}

// Solidity: function subReplaceInt(string jsonBlob, string searchPath, string replacePath, int256 value) view returns(string)
func (c *JsonUtil) SubReplaceInt(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePath string, value *big.Int) (string, error) {
	return jsonSubReplace(jsonBlob, searchPath, []string{replacePath}, []interface{}{value})
}

// Solidity: function subReplaceInt(string jsonBlob, string searchPath, string[] replacePaths, int256[] values) view returns(string)
func (c *JsonUtil) SubReplaceInt0(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePaths []string, values []*big.Int) (string, error) {
	interfaceValues := make([]interface{}, len(values))
	for i, v := range values {
		interfaceValues[i] = v
	}
	return jsonSubReplace(jsonBlob, searchPath, replacePaths, interfaceValues)
}

// Solidity: function subReplaceUint(string jsonBlob, string searchPath, string replacePath, uint256 value) view returns(string)
func (c *JsonUtil) SubReplaceUint(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePath string, value *big.Int) (string, error) {
	return c.SubReplaceInt(ctx, jsonBlob, searchPath, replacePath, value)
}

// Solidity: function subReplaceUint(string jsonBlob, string searchPath, string[] replacePaths, uint256[] values) view returns(string)
func (c *JsonUtil) SubReplaceUint0(ctx precompile.StatefulContext, jsonBlob string, searchPath string, replacePaths []string, values []*big.Int) (string, error) {
	return c.SubReplaceInt0(ctx, jsonBlob, searchPath, replacePaths, values)
}

// Solidity: function remove(string jsonBlob, string path) view returns(string)
func (c *JsonUtil) Remove(ctx precompile.StatefulContext, jsonBlob string, path string) (string, error) {
	validationErr := fastjson.Validate(jsonBlob)
	if validationErr != nil {
		return "", errors.New("invalid JSON")
	}
	updatedJson, _ := sjson.Delete(jsonBlob, path)
	return updatedJson, nil
}

func jsonGet(jsonBlob string, path string) (gjson.Result, error) {
	validationErr := fastjson.Validate(jsonBlob)
	if validationErr != nil {
		return gjson.Result{}, errors.New("invalid JSON")
	}
	return gjson.Get(jsonBlob, path), nil
}

func jsonSet(jsonBlob string, paths []string, values []interface{}) (string, error) {
	updatedJson := jsonBlob
	for i, path := range paths {
		updatedJson, _ = sjson.Set(updatedJson, path, values[i])
	}
	validationErr := fastjson.Validate(updatedJson)
	if validationErr != nil {
		return "", errors.New("invalid JSON")
	}
	return updatedJson, nil
}

func jsonSetRaw(jsonBlob string, paths []string, values []string) (string, error) {
	updatedJson := jsonBlob
	for i, path := range paths {
		updatedJson, _ = sjson.SetRaw(updatedJson, path, values[i])
	}
	validationErr := fastjson.Validate(updatedJson)
	if validationErr != nil {
		return "", errors.New("invalid JSON")
	}
	return updatedJson, nil
}

func jsonSubReplace(jsonBlob string, searchPath string, replacePaths []string, values []interface{}) (string, error) {
	result, err := jsonGet(jsonBlob, searchPath)
	if err != nil {
		return "", err
	}
	updatedJson := jsonBlob
	offset := 0
	for _, r := range result.Array() {
		replacement := r.Raw
		for i, replacePath := range replacePaths {
			replacement, _ = sjson.Set(replacement, replacePath, values[i])
		}
		updatedJson = updatedJson[:r.Index+offset] + replacement + updatedJson[r.Index+offset+len(r.Raw):]
		offset += len(replacement) - len(r.Raw)
	}
	validationErr := fastjson.Validate(updatedJson)
	if validationErr != nil {
		return "", errors.New("invalid JSON")
	}
	return updatedJson, nil
}
