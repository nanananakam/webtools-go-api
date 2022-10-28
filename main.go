package main

import (
	"encoding/json"
	"errors"
	"github.com/ip2location/ip2location-go/v9"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type errorCode string

const (
	errorInvalidInput     errorCode = "ERROR_INVALID_INPUT"
	errorRdapError        errorCode = "ERROR_RDAP_ERROR"
	errorIp2LocationError errorCode = "ERROR_IP2LOCATION_ERROR"
)

type statusCode string

const (
	statusOk    statusCode = "OK"
	statusError statusCode = "ERROR"
)

const reCaptchaSiteVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

type reCaptchaSiteVerifyResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// 必要な項目のみ定義
type rdapEntity struct {
	VcardArray []json.RawMessage `json:"vcardArray"`
	Remarks    []rdapRemark      `json:"remarks"`
}

type rdapRemark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

// 必要な項目のみ定義
type rdapResponse struct {
	Name         string       `json:"name"`
	Country      string       `json:"country"`
	Handle       string       `json:"handle"`
	ParentHandle string       `json:"parentHandle"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Entities     []rdapEntity `json:"entities"`
	Remarks      []rdapRemark `json:"remarks"`
	Port43       string       `json:"port43"`
}

type rdapResponseWithGuess struct {
	RdapResponse    rdapResponse `json:"rdapResponse"`
	RdapResponseRaw string       `json:"rdapResponseRaw"`
	GuessedName     string       `json:"guessedName"`
}

type myRequest struct {
	Input          string `json:"input"`
	RecaptchaToken string `json:"recaptchaToken"`
}

type myResponse struct {
	StatusCode            statusCode                    `json:"statusCode,omitempty"`
	ErrorCode             errorCode                     `json:"errorCode,omitempty"`
	RdapResponseWithGuess rdapResponseWithGuess         `json:"rdapResponseWithGuess,omitempty"`
	Ip2LocationRecord     ip2location.IP2Locationrecord `json:"ip2LocationRecord"`
}

func createErrorResponse(c echo.Context, errorCode errorCode) error {
	response := myResponse{
		StatusCode: statusError,
		ErrorCode:  errorCode,
	}
	return c.JSON(http.StatusBadRequest, response)
}

func createOkResponse(c echo.Context, rdapResponse rdapResponseWithGuess, ip2LocationRecord ip2location.IP2Locationrecord) error {
	response := myResponse{
		StatusCode:            statusOk,
		RdapResponseWithGuess: rdapResponse,
		Ip2LocationRecord:     ip2LocationRecord,
	}
	return c.JSON(http.StatusOK, response)
}

func validateRecaptcha(token string) error {
	recaptchaRequest, err := http.NewRequest(http.MethodPost, reCaptchaSiteVerifyURL, nil)
	if err != nil {
		return err
	}

	recaptchaKey := os.Getenv("RECAPTCHA_KEY")
	q := recaptchaRequest.URL.Query()
	q.Add("secret", recaptchaKey)
	q.Add("response", token)
	recaptchaRequest.URL.RawQuery = q.Encode()

	recaptchaResponse, err := http.DefaultClient.Do(recaptchaRequest)
	if err != nil {
		return err
	}
	defer recaptchaResponse.Body.Close()

	var recaptchaResponseBody reCaptchaSiteVerifyResponse
	if err = json.NewDecoder(recaptchaResponse.Body).Decode(&recaptchaResponseBody); err != nil {
		return err
	}

	if recaptchaResponseBody.Success {
		log.Println("recaptcha succeeded.")
		return nil
	} else {
		log.Println(recaptchaResponseBody.ErrorCodes[0])
		log.Println("recaptcha failed.")
		return errors.New("recaptcha failed")
	}

}

func parseEntity(entities []rdapEntity) string {
	for _, entity := range entities {
		if len(entity.VcardArray) > 0 {
			for _, vcardElement := range entity.VcardArray {
				var vcardElementParsed interface{}
				if err := json.Unmarshal(vcardElement, &vcardElementParsed); err != nil {
					log.Println("parse vcard unexpected error 1")
					return ""
				}
				//vcardの要素が "vcard"の文字列の時は結果を捨てる
				_, ok := vcardElementParsed.(string)
				if !ok {
					vcardElementChildParsed, ok := vcardElementParsed.([]interface{})
					if !ok {
						log.Println("parse vcard unexpected error 2")
						return ""
					}
					for _, vcardElementChildChild := range vcardElementChildParsed {
						vcardElementChildChildParsed, ok := vcardElementChildChild.([]interface{})
						if !ok {
							log.Println("parse vcard unexpected error 3")
						}
						var firstElement, lastElement string
						for _, vcardElementChildChildChild := range vcardElementChildChildParsed {
							vcardElementChildChildChildParsed, ok := vcardElementChildChildChild.(string)
							if ok {
								if firstElement == "" {
									firstElement = vcardElementChildChildChildParsed
								}
								lastElement = vcardElementChildChildChildParsed
							}
						}
						if firstElement == "fn" {
							return lastElement
						}
					}
				}
			}
		}
	}
	return ""
}

func guessNameByRdap(rdapResponse rdapResponse) string {
	if len(rdapResponse.Remarks) > 0 {
		// APNICはresponse直下にremarksがあり、そこに組織名が書いてある。vcardにはJPNICの情報が乗っているのでこちらを使う。
		// ただしLACNICはresponse直下にremarksがあるが、中身は空
		if len(rdapResponse.Remarks[0].Description) > 0 {
			return strings.Join(rdapResponse.Remarks[0].Description, "\n")
		}
	}
	return parseEntity(rdapResponse.Entities)
}

func getIp2Location(ip string) (*ip2location.IP2Locationrecord, error) {
	var db *ip2location.DB
	var err error
	//厳密ではないが、IPv4かIPv6のどちらか判別できれば良いので許容
	ipV4Regex := regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
	if ipV4Regex.MatchString(ip) {
		db, err = ip2location.OpenDB("/IP2LOCATION-LITE-DB11.BIN")
	} else {
		db, err = ip2location.OpenDB("/IP2LOCATION-LITE-DB11.IPV6.BIN")
	}

	if err != nil {
		log.Println("ip2location db open error: " + err.Error())
		res, _ := exec.Command("ls", "-lh", os.Getenv("LAMBDA_TASK_ROOT")).Output()
		log.Println(string(res))
		return nil, err
	}
	dbResponse, err := db.Get_all(ip)
	if err != nil {
		log.Println("ip2location get country error: " + err.Error())
		return nil, err
	}

	return &dbResponse, nil
}

func getRdapResponse(ip string) (*rdapResponseWithGuess, error) {
	rdapRequest, err := http.NewRequest(http.MethodGet, "https://rdap.apnic.net/ip/"+ip, nil)
	if err != nil {
		log.Println("rdap request error: " + err.Error())
		return nil, err
	}

	rdapResponseRaw, err := http.DefaultClient.Do(rdapRequest)
	if err != nil {
		log.Println("rdap request error: " + err.Error())
		return nil, err
	}
	defer rdapResponseRaw.Body.Close()

	rdapResponseRawString, err := io.ReadAll(rdapResponseRaw.Body)

	var rdapResponse rdapResponse
	if err = json.Unmarshal([]byte(rdapResponseRawString), &rdapResponse); err != nil {
		log.Println("rdap response unmarshal error: " + err.Error())
		return nil, err
	}

	rdapResponseWithGuess := rdapResponseWithGuess{
		RdapResponse:    rdapResponse,
		RdapResponseRaw: string(rdapResponseRawString),
		GuessedName:     guessNameByRdap(rdapResponse),
	}

	return &rdapResponseWithGuess, nil

}

func whoisHandler(c echo.Context) error {
	parsedRequest := new(myRequest)
	if err := c.Bind(parsedRequest); err != nil {
		return createErrorResponse(c, errorInvalidInput)
	}

	if err := validateRecaptcha(parsedRequest.RecaptchaToken); err != nil {
		return createErrorResponse(c, errorInvalidInput)
	}

	rdapResponse, err := getRdapResponse(parsedRequest.Input)
	if err != nil {
		return createErrorResponse(c, errorRdapError)
	}

	ip2LocationRecord, err := getIp2Location(parsedRequest.Input)
	if err != nil {
		return createErrorResponse(c, errorIp2LocationError)
	}

	return createOkResponse(c, *rdapResponse, *ip2LocationRecord)
}

func main() {
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"https://www.nanananakam.com", "http://localhost:3000"},
		AllowMethods: []string{http.MethodPost},
	}))

	e.POST("/whois", whoisHandler)
	e.Logger.Fatal(e.Start("0.0.0.0:80"))
}
