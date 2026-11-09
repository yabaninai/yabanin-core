package cictx

import "errors"

var errNoRunner = errors.New("cictx: no command runner")
var errNilContext = errors.New("cictx: nil context")
