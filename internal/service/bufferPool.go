package service

import (
	"bytes"
	"sync"
)

var mediaBufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 8<<10)) // 8kb
	},
}
