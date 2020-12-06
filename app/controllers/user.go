package controllers

import (
	// "encoding/json"
	"errors"
	"revel-golang-todo/app/models"

	"github.com/revel/revel"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

type UserController struct {
	*revel.Controller
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// hashing key
var hmacSecret = []byte{97, 48, 97, 50, 97, 98, 105, 49, 99, 102, 83, 53, 57, 98, 52, 54, 97, 102, 99, 12, 12, 13, 56, 34, 23, 16, 78, 67, 54, 34, 32, 21}

// GET /users
func (c UserController) ListAllUsers() revel.Result {
	var (
		users []models.User
		err   error
	)
	users, err = models.GetUsers()
	if err != nil {
		errResp := buildErrResponse(err, "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}
	c.Response.Status = 200
	return c.RenderJSON(users)
}

// GET /users/:id
func (c UserController) Show(id string) revel.Result {
	var (
		user   models.User
		err    error
		userID bson.ObjectId
	)

	if id == "" {
		errResp := buildErrResponse(errors.New("Please provide user ID"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	userID, err = convertToObjectIdHex(id)
	if err != nil {
		errResp := buildErrResponse(errors.New("Invalid user ID format"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	user, err = models.GetUser(userID)
	if err != nil {
		errResp := buildErrResponse(errors.New("Cannot find user from given User ID"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}

	msg := make(map[string]string)
	msg["result"] = "Successfully"
	msg["username"] = user.Username
	msg["email"] = user.Email
	msg["id"] = string(user.ID)
	c.Response.Status = 200
	return c.RenderJSON(msg)
}

// POST /register
func (c UserController) Register() revel.Result {
	var (
		user models.User
		err  error
	)

	err = c.Params.BindJSON(&user)
	if err != nil {
		errResp := buildErrResponse(errors.New("Please provide valid user details"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	password := user.Password

	bcryptPassword, _ := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)

	user.Password = string(bcryptPassword)

	user, err = models.AddUser(user)
	if err != nil {
		errResp := buildErrResponse(errors.New("Couldn't create user. Please try again"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}

	msg := make(map[string]string)
	msg["result"] = "Created New User Successfully"
	msg["email"] = user.Email
	msg["id"] = string(user.ID)
	c.Response.Status = 201
	return c.RenderJSON(msg)
}

// POST /login
func (c UserController) Login() revel.Result {
	var user models.User
	var credentials Credentials
	err := c.Params.BindJSON(&credentials)
	if err != nil {
		errResp := buildErrResponse(errors.New("Please provide valid username and password"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}
	email := string(credentials.Email)
	password := string(credentials.Password)

	user, err = models.GetUserEmail(email)
	if err != nil {
		errResp := buildErrResponse(errors.New("Incorrect email"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		errResp := buildErrResponse(errors.New("Incorrect password"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	// get token
	tokenString := EncodeToken(email)
	user.Token = tokenString
	err = user.UpdateUser()
	if err != nil {
		errResp := buildErrResponse(errors.New("Couldn't save Token"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	msg := make(map[string]string)
	msg["result"] = "Login Successfully"
	msg["token"] = tokenString
	msg["id"] = string(user.ID)
	c.Response.Status = 202
	return c.RenderJSON(msg)
}

// PUT /logout
func (c UserController) Logout(id string) revel.Result {

	var (
		user   models.User
		err    error
		userID bson.ObjectId
	)

	if id == "" {
		errResp := buildErrResponse(errors.New("Please provide valid user ID"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	userID, err = convertToObjectIdHex(id)
	if err != nil {
		errResp := buildErrResponse(errors.New("Invalid user ID format"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	user, err = models.GetUser(userID)
	if err != nil {
		errResp := buildErrResponse(errors.New("Invalid user"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}

	if user.Token == "" {
		errResp := buildErrResponse(errors.New("User not logged-in"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	user.Token = ""

	err = user.UpdateUser()
	if err != nil {
		errResp := buildErrResponse(errors.New("Couldn't log out. Please try again"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}

	msg := make(map[string]string)
	msg["result"] = "Logout Successfully"
	msg["email"] = user.Email
	msg["id"] = string(user.ID)
	c.Response.Status = 200
	return c.RenderJSON(msg)
}

// PUT /user
func (c UserController) Update() revel.Result {
	var (
		user models.User
		err  error
	)
	err = c.Params.BindJSON(&user)
	if err != nil {
		errResp := buildErrResponse(errors.New("Please provide valid user details"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	err = user.UpdateUser()
	if err != nil {
		errResp := buildErrResponse(errors.New("Couldn't update user. Please try again"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}

	msg := make(map[string]string)
	msg["result"] = "Updated User Successfully"
	msg["email"] = user.Email
	msg["id"] = string(user.ID)
	c.Response.Status = 200
	return c.RenderJSON(msg)
}

// DELETE /users/:id
func (c UserController) Delete(id string) revel.Result {
	var (
		err    error
		user   models.User
		userID bson.ObjectId
	)
	if id == "" {
		errResp := buildErrResponse(errors.New("Please provide user ID"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	userID, err = convertToObjectIdHex(id)
	if err != nil {
		errResp := buildErrResponse(errors.New("Invalid user ID format"), "400")
		c.Response.Status = 400
		return c.RenderJSON(errResp)
	}

	user, err = models.GetUser(userID)
	if err != nil {
		errResp := buildErrResponse(errors.New("Invalid user"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}
	err = user.DeleteUser()
	if err != nil {
		errResp := buildErrResponse(errors.New("Couldn't delete user. Please try again"), "500")
		c.Response.Status = 500
		return c.RenderJSON(errResp)
	}

	msg := make(map[string]string)
	msg["result"] = "Removed User Successfully"
	msg["email"] = user.Email
	msg["id"] = string(user.ID)
	c.Response.Status = 200
	return c.RenderJSON(msg)
}

//////
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
