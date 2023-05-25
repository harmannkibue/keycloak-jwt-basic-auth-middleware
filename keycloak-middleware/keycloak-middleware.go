package keycloak_middleware

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

type AuthMiddlewareStruct struct {
}

func NewAuthMiddleware() *AuthMiddlewareStruct {
	return &AuthMiddlewareStruct{}
}

// AuthMiddleware is used to inject http basic auth authentication as a middleware -.
func (authStruct *AuthMiddlewareStruct) AuthMiddleware() gin.HandlerFunc {

	return func(ctx *gin.Context) {
		// Getting which gateway is used -.
		authType := ctx.GetHeader("Gateway")

		log.Println("KEYCLOAK HEADERS ", ctx.Request.Header)

		if authType == "basic" {
			//	Set the organisation Id for the client -.
			orgId := ctx.GetHeader("orgid")
			log.Println("IN BASIC AUTH MIDDLEWARE ORGANISATION ID ISS ", orgId)

			ctx.Set("ORGANISATION-ID", orgId)
			ctx.Set("AUTH-TYPE", authType)
		} else if authType == "jwt" {
			// Done on separate IF to take care of the bug in HA-Proxy gateway keycloak -.
			//	Set the organisation Id for the client -.
			orgId, err := authStruct.extractUUIDFromJsonHeaders(ctx.GetHeader("orgid"))

			// Checking if there is an error in extracting uuid -.
			if err != nil {
				ctx.JSON(http.StatusForbidden, gin.H{
					"error": "Forbidden!",
				})
				// Abort processing of the request
				ctx.Abort()
				// Return from the middleware function
				return
			}

			ctx.Set("ORGANISATION-ID", orgId)
			ctx.Set("AUTH-TYPE", authType)
			ctx.Set("AUTH-HEADERS", ctx.Request.Header)
		} else {
			//	trying to access our gateway the wrong way than the supported ways -.
			ctx.JSON(http.StatusForbidden, gin.H{
				"error": "Forbidden!",
			})

			// Abort processing of the request
			ctx.Abort()

			// Return from the middleware function
			return
		}

	}
}

func (authStruct *AuthMiddlewareStruct) extractUUIDFromJsonHeaders(jsonStr string) (string, error) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return "", err
	}

	for key := range data {
		return key, nil // Assuming the UUID is always the first key in the map
	}

	return "", fmt.Errorf("UUID not found in JSON")
}
