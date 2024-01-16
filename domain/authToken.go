package domain

import (
	"github.com/cbdavid14/ms-api-go-banking-auth/errs"
	"github.com/cbdavid14/ms-api-go-banking-auth/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthToken struct {
	token *jwt.Token
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token}
}

func NewAccessTokenFromRefreshToken(refreshToken string) (string, *errs.AppError) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_KEY), nil
	})
	if err != nil {
		logger.Error("Error while parsing refresh token: " + err.Error())
		return "", errs.NewAuthenticationError("Invalid or expired refresh token")
	}
	r := token.Claims.(*RefreshTokenClaims)
	accessTokenClaims := r.AccessTokenClaims()
	authToken := NewAuthToken(accessTokenClaims)
	return authToken.NewAccessToken()
}

func (t AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedString, err := t.token.SignedString([]byte(SECRET_KEY))
	if err != nil {
		logger.Error("Error while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("Cannot generate access token")
	}
	return signedString, nil
}

func (t AuthToken) NewRefreshToken() (string, *errs.AppError) {
	c := t.token.Claims.(AccessTokenClaims)
	refreshClaims := c.RefreshTokenClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedString, err := token.SignedString([]byte(SECRET_KEY))
	if err != nil {
		logger.Error("Error while signing refresh token: " + err.Error())
		return "", errs.NewUnexpectedError("Cannot generate refresh token")
	}
	return signedString, nil
}
