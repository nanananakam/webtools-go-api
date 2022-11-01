package echoHeader

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func Handler(c echo.Context) error {
	return c.JSON(http.StatusOK, c.Request().Header)
}
