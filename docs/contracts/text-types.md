# Text input contract

`pkg/dataclass` accepts the following caller-declared UTF-8 text types, in the
order returned by `SupportedTextTypes()`. Limits apply to raw bytes, not runes.

| Type | Supported | Maximum bytes | Typed refusals | Purpose | Boundary test |
| --- | --- | --- | --- | --- | --- |
| plain | yes | 65536 | ErrTooLarge, ErrNotUTF8, ErrEmpty | Bounded prose and chat input | TestTextTypes_LimitsExactBoundary/plain |
| markdown | yes | 262144 | ErrTooLarge, ErrNotUTF8, ErrEmpty | Longer formatted documents | TestTextTypes_LimitsExactBoundary/markdown |
| json | yes | 262144 | ErrTooLarge, ErrNotUTF8, ErrEmpty | Bounded textual structured input | TestTextTypes_LimitsExactBoundary/json |
| code | yes | 524288 | ErrTooLarge, ErrNotUTF8, ErrEmpty | Larger source and configuration text | TestTextTypes_LimitsExactBoundary/code |
| form | yes | 65536 | ErrTooLarge, ErrNotUTF8, ErrEmpty | Caller-declared form text | TestTextTypes_LimitsExactBoundary/form |

`ValidateText` checks, in order: supported type, valid UTF-8, maximum byte
length, then nonempty/non-whitespace content. An input at the limit is accepted;
one byte above it returns `ErrTooLarge`. Invalid UTF-8 wins over an oversized
payload; an unsupported type wins over all payload errors. Type validation
checks these text boundaries, not JSON syntax, source-code safety or form fields.

`DetectType never returns form`: form has no reliable structural signature and
must be declared by the caller. Detection of other types is best effort, not a
content-security guarantee.

The following tests specify the shared boundaries:

- `TestTextTypes_LimitIsBytesNotRunes`: multibyte input consumes its UTF-8 byte length.
- `TestTextTypes_CheckOrderIsFixedAndObservable`: refusal precedence is stable.
- `TestTextTypes_EmptyAndWhitespaceRefused`: whitespace-only payloads are rejected.
- `TestTextTypes_ParseRefusesUnknown`: values outside the closed set return `ErrUnsupportedType`.

[Implementation](../../pkg/dataclass/texttypes.go) ·
[Boundary tests](../../pkg/dataclass/texttypes_test.go) ·
[Matrix consistency test](../../pkg/dataclass/texttypes_matrix_test.go)
