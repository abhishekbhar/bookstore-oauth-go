package oauth

import (
	"fmt"
	"time"
	"net/http"
	"strings"
	"strconv"
	"encoding/json"
	"github.com/abhishekbhar/bookstore-oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)


const (
	headerXPublic 	= "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,

	}
)


type oAuthClient struct {}


type oauthInterface interface {
	
}


type accessToken struct {
	Id 			string 	`json:"Id"`
	UserId 		int64 	`json:"user_id"`
	ClientId 	int64 	`json:"client_id"`
}


func IsPublic(request *http.Request ) bool{
	if request == nil {
		return true
	}

	val, err := strconv.ParseBool(request.Header.Get(headerXPublic))

	if err!=nil {
		return true
	}

	return val
}


func AuthenticateRequest(request *http.Request) *errors.RestErr{
	if request == nil {
		return nil
	}

	cleanRequest(request)

	access_token := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if access_token == "" {
		return nil
	}

	at, err := getAccessToken(access_token)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerId, fmt.Sprintf("%v",at.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v",at.ClientId))

	return nil
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10,64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10,64)
	if err != nil {
		return 0
	}

	return clientId
}




func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Invalid rest client response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr		
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access token")
		}

		if restErr.Status == 404 {
			return nil,nil
		}
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal access token response")
	}

	return &at, nil

}