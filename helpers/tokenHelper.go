package helper

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type AccessDetails struct {
	AccessToken		string	`json:"accesstoken"`
	RefreshToken	string	`json:"refreshtoken"`
	RTHash			string	`json:"rthash"`
	UserId			string	`json:"userid"`
	AtExpires		int64	`bson:"atexpires" json:"atexpires"`
	RtExpires		int64	`bson:"rtexpires" json:"rtexpires"`
	TUuid			string	`json:"tuuid"`
	Expired			bool	`json:"expired"`
}
var (
	PubKey *rsa.PublicKey
	PrvKey *rsa.PrivateKey
)

//Генерирует открытый и закрытый ключи, сохраняя их в корне проекта
func GenerateRSAKeys() {
	// generate key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privatePem, _ := os.Create("private.pem")
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private pem: %s \n", err)
		os.Exit(1)
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicPem1, _ := os.Create("public.pem")
	var publicPemStr bytes.Buffer
	err1 := pem.Encode(publicPem1, publicKeyBlock)
	err2 := pem.Encode(&publicPemStr, publicKeyBlock)
	if err1 != nil && err2 != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}

	_ = os.Setenv("PUBLIC_KEY", publicPemStr.String())
}

//Извлекает открытый и закрытый ключи из pem файлов
func GetKeysRSA() {
	_, errPrv := os.Stat("private.pem")
	_, errPub := os.Stat("public.pem")

	if os.IsNotExist(errPrv) || os.IsNotExist(errPub) {
		GenerateRSAKeys()
	}
	keyPrvData, _ := ioutil.ReadFile("private.pem")
	keyPubData, _ := ioutil.ReadFile("public.pem")

	var errPrvPem, errPubPem error
	PrvKey, errPrvPem = jwt.ParseRSAPrivateKeyFromPEM(keyPrvData)
	PubKey, errPubPem = jwt.ParseRSAPublicKeyFromPEM(keyPubData)
	if errPrvPem != nil || errPubPem != nil {
		panic("KeyError")
	}
}

//Извлечкает токен из заголовка запроса
func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

//Проверяет достоверность и время жизни токена
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return PubKey, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

//Если токен достоверен, то извлекает из токена полезную часть
func ExtractTokenMetadata(req *http.Request) (*AccessDetails, error) {
	ad := AccessDetails{}
	ad.Expired = false

	token, err := VerifyToken(req)
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0  {
				ad.Expired = true
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if token == nil {
		return nil, fmt.Errorf("unauthorized")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userid, ok1 := claims["userid"].(string)
		tuuid, ok2 := claims["tuuid"].(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("unauthorized")
		}
		ad.UserId = userid
		ad.TUuid = tuuid

		return &ad, nil
	}

	return nil, fmt.Errorf("unauthorized")
}

//Генерирует Access и Refresh токены
func CreateToken(userid string) (*AccessDetails, error) {
	ad := &AccessDetails{}

	atNow := time.Now().Local().Add(time.Minute * 1)
	rtNow := time.Now().Local().Add(time.Minute * 2)

	ad.AtExpires = atNow.Unix()
	ad.RtExpires = rtNow.Unix()

	ad.TUuid = uuid.NewV4().String()
	ad.UserId = userid

	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["pk"] = os.Getenv("PUBLIC_KEY")
	rtClaims["tuuid"] = ad.TUuid
	rtClaims["userid"] = ad.UserId
	rtClaims["exp"] = ad.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodRS512, rtClaims)
	var err error
	ad.RefreshToken, err = rt.SignedString(PrvKey)
	ad.RTHash = HashPassword(ad.RefreshToken)
	if err != nil {
		return nil, err
	}

	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["pk"] = os.Getenv("PUBLIC_KEY")
	atClaims["tuuid"] = ad.TUuid
	atClaims["userid"] = ad.UserId
	atClaims["exp"] = ad.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodRS512, atClaims)
	ad.AccessToken, err = at.SignedString(PrvKey)
	if err != nil {
		return nil, err
	}

	return ad, nil
}

//Хеширует переданный ей Refresh токен
func HashPassword(password string) string {
	passBytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}

	return string(passBytes)
}

//Сравнивает переданные ей хэшированный Refresh токен bcrypt с его возможным эквивалентом в открытом тексте
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("login or passowrd is incorrect")
		check = false
	}

	return check, msg
}
