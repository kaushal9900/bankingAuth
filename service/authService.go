package service

import (
	"bankingAuth/domain"
	"bankingAuth/dto"

	"github.com/kaushal9900/banking-lib/errs"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var err *errs.AppError
	var login *domain.Login
	if login, err = s.repo.FindBy(req.Username, req.Password); err != nil {
		return nil, err
	}
	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)
	var accessToken, refreshToken string
	if accessToken, err = authToken.NewAccessToken(); err != nil {
		return nil, err
	}
	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}
func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
