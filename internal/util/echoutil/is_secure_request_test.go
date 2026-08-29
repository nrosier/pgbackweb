package echoutil

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestIsSecureRequest(t *testing.T) {
	t.Run("plain HTTP request", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.False(t, IsSecureRequest(c))
	})

	t.Run("direct TLS request", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.TLS = &tls.ConnectionState{}
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.True(t, IsSecureRequest(c))
	})
}
