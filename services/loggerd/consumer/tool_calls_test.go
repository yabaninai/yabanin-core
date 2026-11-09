package consumer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractToolCallNames_CompletionDocument(t *testing.T) {
	sample := `{"id":"r1","choices":[{"index":0,"finish_reason":"tool_calls","message":{
		"role":"assistant","tool_calls":[
			{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Vienna\"}"}},
			{"id":"c2","type":"function","function":{"name":"read_file","arguments":"{}"}}
		]}}]}`

	assert.Equal(t, []string{"get_weather", "read_file"}, extractToolCallNames(sample))
}

func TestExtractToolCallNames_StreamedFrames(t *testing.T) {
	sample := "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"s1\",\"function\":{\"name\":\"sea\",\"arguments\":\"\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"q\\\":1}\"}}]}}]}\n\n" +
		"data: [DONE]\n\n"

	// Fragment continuations carry no name — the aggregate must not duplicate.
	assert.Equal(t, []string{"sea"}, extractToolCallNames(sample))
}

func TestExtractToolCallNames_DegenerateSamples(t *testing.T) {
	assert.Nil(t, extractToolCallNames(""))
	assert.Nil(t, extractToolCallNames("not json at all"))
	assert.Nil(t, extractToolCallNames(`{"choices":[]}`))
	assert.Nil(t, extractToolCallNames(`{"choices":[{"message":{"tool_calls":42}}]}`))
	// Truncated mid-object: no complete call — honest empty.
	assert.Nil(t, extractToolCallNames(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"trun`))
}
