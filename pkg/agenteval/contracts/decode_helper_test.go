package contracts

import (
	"encoding/json"
	"strings"
)

func jsonNewDecoder(data string) *json.Decoder {
	return json.NewDecoder(strings.NewReader(data))
}
