package handler

import (
	"net/http"
	"strconv"
	"sync/atomic"
)

var (
	count int64
)

func Count(w http.ResponseWriter, r *http.Request) {
	new := atomic.AddInt64(&count, 1)
	w.Write([]byte(strconv.FormatInt(new, 10)))
}
