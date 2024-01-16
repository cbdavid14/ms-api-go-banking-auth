package domain

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const (
	SECRET_KEY                 = "secretKeySample"
	ACCESS_TOKEN_DURATION_HOUR = time.Hour
	REFRESH_TOKEN_DURATION     = time.Hour * 24 * 30
)

type RefreshTokenClaims struct {
	TokenType  string   `json:"token_type"`
	CustomerId string   `json:"cid"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"un"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	jwt.StandardClaims
}

func (atc AccessTokenClaims) IsUserRole() bool {
	return atc.Role == "user"
}

func (atc AccessTokenClaims) IsValidAccountId(accountId string) bool {
	if accountId != "" {
		// Role User can access only his accounts
		for _, account := range atc.Accounts {
			if account == accountId {
				return true
			}
		}
		return false
	}
	// Role Admin can access all accounts
	return true
}

func (atc AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if atc.CustomerId != urlParams["customer_id"] {
		return false
	}
	if !atc.IsValidAccountId(urlParams["account_id"]) {
		return false
	}
	return true
}

func (atc AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType:  "refresh_token",
		CustomerId: atc.CustomerId,
		Accounts:   atc.Accounts,
		Username:   atc.Username,
		Role:       atc.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (rtc RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		CustomerId: rtc.CustomerId,
		Accounts:   rtc.Accounts,
		Username:   rtc.Username,
		Role:       rtc.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION_HOUR).Unix(),
		},
	}
}
