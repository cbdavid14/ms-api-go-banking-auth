package dto

import (
	"errors"
	"github.com/cbdavid14/ms-api-go-banking-auth/domain"
	"github.com/dgrijalva/jwt-go"
)

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {
	//1. invalid token
	//2. token expired
	_, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.SECRET_KEY), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if ok := errors.As(err, &vErr); ok {
			return vErr
		}
	}
	return nil
}
