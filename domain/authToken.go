package domain

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/kaushal9900/banking-lib/errs"
	"github.com/kaushal9900/banking-lib/logger"
)

const HMAC_SAMPLE_SECRET = "secretkey"

type AuthToken struct {
	token *jwt.Token
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token: token}
}

func (t AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedString, err := t.token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("cannot generate access token")
	}
	return signedString, nil
}
