package domain

import "github.com/cbdavid14/ms-api-go-banking-auth/errs"

type AuthRepository interface {
	FindByCredentials(username string, password string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(refreshToken string) *errs.AppError
}
