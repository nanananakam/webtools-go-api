package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"nanananakam-api-go/echoHeader"
	"nanananakam-api-go/whois"
	"net/http"
)

func healthCheckHandler(c echo.Context) error {
	if whois.HealthCheck() {
		return c.String(http.StatusOK, "Ok")
	} else {
		return c.String(http.StatusInternalServerError, "NG")
	}
}

func main() {
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"https://www.nanananakam.com", "http://localhost:3000"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))

	e.GET("/_chk", healthCheckHandler)
	e.POST("/whois", whois.Handler)
	e.POST("/echoHeader", echoHeader.Handler)
	e.Logger.Fatal(e.Start("0.0.0.0:80"))
}
