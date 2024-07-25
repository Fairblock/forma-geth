package abi

const (
	Base64ABI       = "[{\"type\":\"function\",\"name\":\"decode\",\"inputs\":[{\"name\":\"_data\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"decodeURL\",\"inputs\":[{\"name\":\"_data\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"encode\",\"inputs\":[{\"name\":\"_data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"encodeURL\",\"inputs\":[{\"name\":\"_data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"}]"
	CompressABI     = "[{\"type\":\"function\",\"name\":\"compress\",\"inputs\":[{\"name\":\"_data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"decompress\",\"inputs\":[{\"name\":\"_data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"pure\"}]"
	IntegersABI     = "[{\"type\":\"function\",\"name\":\"fromHexString\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"toHexString\",\"inputs\":[{\"name\":\"_i\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"_length\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"toHexString\",\"inputs\":[{\"name\":\"_i\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"toString\",\"inputs\":[{\"name\":\"_i\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"toString\",\"inputs\":[{\"name\":\"_i\",\"type\":\"int256\",\"internalType\":\"int256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"}]"
	JsonStoreABI    = "[{\"type\":\"function\",\"name\":\"clear\",\"inputs\":[{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"exists\",\"inputs\":[{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"exists\",\"inputs\":[{\"name\":\"_key\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"get\",\"inputs\":[{\"name\":\"_key\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"get\",\"inputs\":[{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"prepaid\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"prepaid\",\"inputs\":[{\"name\":\"_key\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"prepay\",\"inputs\":[{\"name\":\"_numSlots\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"set\",\"inputs\":[{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"uri\",\"inputs\":[{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"uri\",\"inputs\":[{\"name\":\"_key\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"}]"
	JsonUtilABI     = "[{\"type\":\"function\",\"name\":\"compact\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"dataURI\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"exists\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"get\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"getBool\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"getInt\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"int256\",\"internalType\":\"int256\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"getRaw\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"getUint\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"remove\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"set\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"string[]\",\"internalType\":\"string[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"set\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setBool\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"bool[]\",\"internalType\":\"bool[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setBool\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setInt\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"int256[]\",\"internalType\":\"int256[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setInt\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"int256\",\"internalType\":\"int256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setRaw\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_rawBlob\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setRaw\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_rawBlobs\",\"type\":\"string[]\",\"internalType\":\"string[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setUint\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"setUint\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplace\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"string[]\",\"internalType\":\"string[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplace\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplaceBool\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"bool[]\",\"internalType\":\"bool[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplaceBool\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplaceInt\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"int256\",\"internalType\":\"int256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplaceInt\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"int256[]\",\"internalType\":\"int256[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplaceUint\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_value\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"subReplaceUint\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_search_path\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_replace_paths\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"_values\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"validate\",\"inputs\":[{\"name\":\"_jsonBlob\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"}]"
	NativeMinterABI = "[{\"type\":\"function\",\"name\":\"burn\",\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"mint\",\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"minter\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setMinter\",\"inputs\":[{\"name\":\"_newMinter\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"_newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"}]"
	StringsABI      = "[{\"type\":\"function\",\"name\":\"contains\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_substr\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"endsWith\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_substr\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"equal\",\"inputs\":[{\"name\":\"_a\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_b\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"equalCaseFold\",\"inputs\":[{\"name\":\"_a\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_b\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"indexOf\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_substr\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"padEnd\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_len\",\"type\":\"uint16\",\"internalType\":\"uint16\"},{\"name\":\"_pad\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"padStart\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_len\",\"type\":\"uint16\",\"internalType\":\"uint16\"},{\"name\":\"_pad\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"repeat\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_count\",\"type\":\"uint16\",\"internalType\":\"uint16\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"replace\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_old\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_new\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_n\",\"type\":\"uint16\",\"internalType\":\"uint16\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"replaceAll\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_old\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_new\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"split\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_delim\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string[]\",\"internalType\":\"string[]\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"startsWith\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"_substr\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"toLowerCase\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"toUpperCase\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"trim\",\"inputs\":[{\"name\":\"_str\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"pure\"}]"
	DecryptionABI   = "[{\"type\":\"function\",\"name\":\"decrypt\",\"inputs\":[{\"name\":\"privateKeyByte\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"cipherBytes\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"id\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getPK\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"setPK\",\"inputs\":[{\"name\":\"_pk\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"}]"
)
