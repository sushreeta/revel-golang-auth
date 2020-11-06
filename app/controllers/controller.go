package controllers

import (
	"fmt"
	"strconv"

	"gopkg.in/mgo.v2/bson"
)

type CtrlErr map[string]interface{}

func parseUintOrDefault(intStr string, _default uint64) uint64 {
	if value, err := strconv.ParseUint(intStr, 0, 64); err != nil {
		return _default
	} else {
		return value
	}
}

func parseIntOrDefault(intStr string, _default int64) int64 {
	if value, err := strconv.ParseInt(intStr, 0, 64); err != nil {
		return _default
	} else {
		return value
	}
}

func convertToObjectIdHex(id string) (result bson.ObjectId, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Unable to convert %v to object id", id)
		}
	}()

	return bson.ObjectIdHex(id), err
}

func buildErrResponse(err error, errorCode string) CtrlErr {
	ctrlErr := CtrlErr{}
	ctrlErr["error_message"] = err.Error()
	ctrlErr["error_code"] = errorCode
	return ctrlErr
}

// func Authenticate(c *revel.Controller) revel.Result {

// 	notAuth := []string{"/register", "/login"}
// 	requestPath := c.Request.URL.Path
// 	for _, value := range notAuth {

// 		if value == requestPath {
// 			return nil
// 		}
// 	}

// 	tokenString, err := GetTokenString(c)
// 	if err != nil {
// 		errResp := buildErrResponse(errors.New("Authentication failed!"), "401")
// 		c.Response.Status = 401
// 		return c.RenderJSON(errResp)
// 	}

// 	var claims jwt.MapClaims
// 	claims, err = DecodeToken(tokenString)
// 	if err != nil {
// 		errResp := buildErrResponse(errors.New("Authentication failed!"), "401")
// 		c.Response.Status = 401
// 		return c.RenderJSON(errResp)
// 	}

// 	email, found := claims["email"]
// 	if !found {
// 		errResp := buildErrResponse(errors.New("Authentication failed!"), "401")
// 		c.Response.Status = 401
// 		return c.RenderJSON(errResp)
// 	}

// 	_, err = models.GetUserEmail(email.(string))
// 	if err != nil {
// 		errResp := buildErrResponse(errors.New("Authentication failed!"), "401")
// 		c.Response.Status = 401
// 		return c.RenderJSON(errResp)
// 	}
// 	return nil
// }

// func GetTokenString(c *revel.Controller) (tokenString string, err error) {
// 	var errAuthHeaderNotFound = errors.New("authorization header not found")
// 	authHeader := c.Request.GetHttpHeader("auth")
// 	fmt.Println(authHeader)
// 	if authHeader == "" {
// 		return "", errAuthHeaderNotFound
// 	}
// 	tokenString = authHeader
// 	return tokenString, nil
// }

// func EncodeToken(email string) string {

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"email": email,
// 		"nbf":   time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
// 	})

// 	tokenString, _ := token.SignedString(hmacSecret)

// 	return tokenString
// }

// func DecodeToken(tokenString string) (jwt.MapClaims, error) {

// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return hmacSecret, nil
// 	})

// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok && !token.Valid {
// 		return nil, err
// 	}
// 	return claims, nil
// }

// func init() {

// 	revel.InterceptFunc(Authenticate, revel.BEFORE, &UserController{})
// }
