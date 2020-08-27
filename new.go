package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	router = gin.Default()
)

func main() {

	router.POST("/login", Login)

	router.POST("/refresh", Refresh)

	router.POST("/delete", Delete)

	router.POST("/delete-all", DeleteAll)
	log.Fatal(router.Run(":8080"))
}

type TokenDetails struct {
	AccessToken      string
	RefreshToken     string
	RefreshTokenHash string
	AtExpires        int64
	RtExpires        int64
}

type Token struct {
	ID               uint64
	RefreshTokenHash string
	RtExpires        int64
}

type User struct {
	ID uint64 `json:"id"`
}

var user = User{
	ID: 1,
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if user.ID != u.ID {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	ts, err := CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	saveErr := CreateAuth(user.ID, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func CreateToken(userid uint64) (*TokenDetails, error) {
	td := &TokenDetails{}

	td.AtExpires = time.Now().Add(time.Second * 30).Unix()
	td.RtExpires = time.Now().Add(time.Second * 60).Unix()

	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "eyJleHAiOjE1OTgyMTQ1ODksInVzZXJfaWQiOjF9")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	td.RefreshToken = td.RefreshToken
	if err != nil {
		return nil, err
	}

	return td, nil
}

func CreateAuth(userid uint64, td *TokenDetails) error {
	uri := "mongodb://localhost:27017"
	sess, err := mgo.Dial(uri)
	if err != nil {
		fmt.Printf("Can't connect to mongo, go error %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()
	sess.SetSafe(&mgo.Safe{})
	collection := sess.DB("auth").C("tokens")
	td.RefreshToken = td.RefreshToken
	if err != nil {
		fmt.Printf("Use another refresh token", err)
		os.Exit(1)
	}
	td.RefreshTokenHash, _ = HashPassword(td.RefreshToken)
	err = collection.Insert(&Token{userid, td.RefreshTokenHash, td.RtExpires})
	return err
}

func Refresh(c *gin.Context) {
	ctx := context.Background()
	tok := c.Query("refresh_token")
	uri := "mongodb://localhost:27017"
	clientOpts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Disconnect(ctx) }()
	sess, err := mgo.Dial(uri)
	if err != nil {
		fmt.Printf("Can't connect to mongo, go error %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()
	sess.SetSafe(&mgo.Safe{})
	collection := sess.DB("auth").C("tokens")
	result := Token{}
	dbSize, _ := collection.Count()
	fmt.Printf("dbSize1111", string(dbSize))
	err = collection.Find(nil).Skip(dbSize - 1).One(&result)
	if err != nil {
		error := map[string]string{
			"error": "Forbidden",
		}
		c.JSON(http.StatusForbidden, error)
		return
	}
	if CheckPasswordHash(tok, result.RefreshTokenHash) == true {
		if int64(result.RtExpires) >= int64(time.Now().Unix()) {
			ts, err := CreateToken(result.ID)
			ts.RefreshToken = ts.RefreshToken
			if err != nil {
				error := map[string]string{
					"error": "Forbidden",
				}
				c.JSON(http.StatusForbidden, error)
				return
			}
			callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
				saveErr := CreateAuth(user.ID, ts)
				if saveErr != nil {
					error := map[string]string{
						"error": "Forbidden",
					}
					c.JSON(http.StatusForbidden, error)
				}

				tokens := map[string]string{
					"access_token":  ts.AccessToken,
					"refresh_token": ts.RefreshToken,
				}
				collection.Remove(bson.M{"refreshtokenhash": result.RefreshTokenHash})
				c.JSON(http.StatusOK, tokens)
				return nil, nil
			}
			session, err := client.StartSession()
			if err != nil {
				panic(err)
			}
			defer session.EndSession(ctx)

			result, err := session.WithTransaction(ctx, callback)
			if err != nil {
				panic(err)
			}
			fmt.Printf("result: %v\n", result)

		} else {
			error := map[string]string{
				"error": "Update your token"}
			c.JSON(http.StatusForbidden, error)
		}

	} else {
		error := map[string]string{
			"error": "Forbidden"}
		c.JSON(http.StatusForbidden, error)
	}

}

func Delete(c *gin.Context) {
	t := c.Query("refresh_token")
	uri := "mongodb://localhost:27017"
	sess, err := mgo.Dial(uri)
	if err != nil {
		fmt.Printf("Can't connect to mongo, go error %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()
	sess.SetSafe(&mgo.Safe{})
	collection := sess.DB("auth").C("tokens")
	result := Token{}
	dbSize, _ := collection.Count()
	fmt.Printf("dbSize", string(dbSize))
	err = collection.Find(nil).Skip(dbSize - 1).One(&result)
	if err != nil {
		error := map[string]string{
			"error": "Forbidden",
		}
		c.JSON(http.StatusForbidden, error)
		return
	}
	if CheckPasswordHash(t, result.RefreshTokenHash) == true {
		err = collection.Remove(bson.M{"refreshtokenhash": result.RefreshTokenHash})
		if err != nil {
			fmt.Printf("remove fail %v\n", err)
			os.Exit(1)
		}
	}
}

func DeleteAll(c *gin.Context) {
	id, _err := strconv.Atoi(c.Query("id"))
	if _err != nil {
		response := map[string]bool{
			"sucess": false,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}

	uri := "mongodb://localhost:27017"
	sess, err := mgo.Dial(uri)
	if err != nil {
		fmt.Printf("Can't connect to mongo, go error %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()
	sess.SetSafe(&mgo.Safe{})
	collection := sess.DB("auth").C("tokens")

	_, error := collection.RemoveAll(bson.M{"id": id})
	if error != nil {
		response := map[string]bool{
			"sucess": false,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	response := map[string]bool{
		"sucess": true,
	}
	c.JSON(http.StatusOK, response)
}
