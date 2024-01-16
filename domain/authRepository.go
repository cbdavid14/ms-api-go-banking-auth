package domain

import (
	"database/sql"
	"errors"
	"github.com/cbdavid14/ms-api-go-banking-auth/errs"
	"github.com/cbdavid14/ms-api-go-banking-auth/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepositoryDB struct {
	client *sqlx.DB
}

func NewAuthRepositoryDB(client *sqlx.DB) AuthRepositoryDB {
	return AuthRepositoryDB{client}
}

func (a AuthRepositoryDB) FindByCredentials(username string, password string) (*Login, *errs.AppError) {
	var login Login
	query := `SELECT u.username, u.customer_id, u.role, group_concat(a.account_id) as accounts_numbers FROM users u
                  LEFT JOIN accounts a ON a.customer_id = u.customer_id
                WHERE username = ? and password = ?
                GROUP BY u.username, a.customer_id, u.role`

	err := a.client.Get(&login, query, username, password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.NewAuthenticationError("Invalid credentials")
		} else {
			logger.Error("Error while querying logins table " + err.Error())
			return nil, errs.NewUnexpectedError("Error while querying logins table")
		}
	}
	return &login, nil
}

func (a AuthRepositoryDB) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	// generate the refresh token
	var appErr *errs.AppError
	var refreshToken string
	if refreshToken, appErr = authToken.NewRefreshToken(); appErr != nil {
		return "", appErr
	}

	// store it in the store
	sqlInsert := "insert into refresh_token_store (refresh_token) values (?)"
	_, err := a.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}
func (a AuthRepositoryDB) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "select refresh_token from refresh_token_store where refresh_token = ?"
	var token string
	err := a.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("unexpected database error")
		}
	}
	return nil
}
