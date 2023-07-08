package handler

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

var (
	count int64
)

func Count() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		new := atomic.AddInt64(&count, 1)
		fmt.Fprintf(w, "%d", new)
	}
}
