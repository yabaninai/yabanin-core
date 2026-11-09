package apierrors

import "encoding/json"

// responsesError always carries param and code (explicit null when empty) —
// the Responses surface contract, pinned by golden tests. Field order
// (message,type,param,code) matches the previous writer byte for byte.
type responsesError struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    *string `json:"code"`
}

type responsesEnvelope struct {
	Error responsesError `json:"error"`
}

// Responses renders e in the OpenAI Responses error envelope with param
// normalised to null when the gateway omitted it, and code present (null when
// empty). The HTTP status is preserved by the response itself, not this body.
func Responses(e *E) []byte {
	env := responsesEnvelope{}
	if e != nil {
		env.Error.Message = e.Message
		env.Error.Type = e.Type
		if e.Param != "" {
			p := e.Param
			env.Error.Param = &p
		}
		if e.Code != "" {
			c := e.Code
			env.Error.Code = &c
		}
	}
	out, err := json.Marshal(env)
	if err != nil {
		return []byte(`{"error":{"message":"encode failed","type":"api_error","param":null,"code":null}}`)
	}
	return out
}
