package services

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"path/filepath"

	"github.com/disintegration/imaging"

	"github.com/Bananenpro/log"

	hid "github.com/Bananenpro/h-id"

	"github.com/Bananenpro/h-id/config"
	"github.com/Bananenpro/h-id/repos"
)

type UserService interface {
	Find(ctx context.Context, id string) (*repos.UserModel, error)
	Create(ctx context.Context, name, email, password string) (*repos.UserModel, error)
	Update(ctx context.Context, id, name string) error
	SetProfilePicture(userID string, img image.Image) error
	LoadProfilePicture(userID string, size int, writer io.Writer) error
	ProfilePictureETag(userID string, size int) string
	Delete(ctx context.Context, id, password string) error
}

type userService struct {
	userRepo    repos.UserRepository
	authService AuthService
}

func NewUserService(userRepository repos.UserRepository, authService AuthService) UserService {
	return &userService{
		userRepo:    userRepository,
		authService: authService,
	}
}

func (u *userService) Find(ctx context.Context, id string) (*repos.UserModel, error) {
	return u.userRepo.Find(ctx, id)
}

func (u *userService) Create(ctx context.Context, name, email, password string) (*repos.UserModel, error) {
	passwordHash, err := u.authService.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user, err := u.userRepo.Create(ctx, name, email, passwordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *userService) Update(ctx context.Context, id, name string) error {
	return u.userRepo.Update(ctx, id, name)
}

func (u *userService) SetProfilePicture(userID string, img image.Image) error {
	size := img.Bounds().Dx()
	if img.Bounds().Dx() > img.Bounds().Dy() {
		size = img.Bounds().Dy()
	}
	img = imaging.CropCenter(img, size, size)

	file, err := os.Create(profilePicturePath(userID))
	if err != nil {
		return fmt.Errorf("set profile picture: %w", err)
	}
	defer file.Close()

	err = imaging.Encode(file, imaging.Resize(img, config.ProfilePictureSize(), config.ProfilePictureSize(), imaging.Linear), imaging.JPEG, imaging.JPEGQuality(90))
	if err != nil {
		return fmt.Errorf("set profile picture: %w", err)
	}
	return nil
}

func (u *userService) LoadProfilePicture(userID string, size int, writer io.Writer) error {
	var reader io.Reader
	file, err := os.Open(profilePicturePath(userID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			reader = bytes.NewBuffer(hid.DefaultProfilePicture)
		} else {
			return fmt.Errorf("get profile picture: %w", err)
		}
	} else {
		reader = file
	}
	defer file.Close()
	img, err := imaging.Decode(reader)
	if err != nil {
		return fmt.Errorf("get profile picture: %w", err)
	}
	img = imaging.Resize(img, size, size, imaging.Linear)
	err = imaging.Encode(writer, img, imaging.JPEG)
	if err != nil {
		return fmt.Errorf("get profile picture: %w", err)
	}
	return nil
}

func (u *userService) ProfilePictureETag(userID string, size int) string {
	stat, err := os.Stat(profilePicturePath(userID))
	if err != nil {
		return fmt.Sprintf("%x", md5.Sum([]byte("default")))
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s%d", stat.Name(), stat.ModTime().UnixMilli()+stat.Size()+int64(size)))))
}

func profilePicturePath(userID string) string {
	return filepath.Join(config.ProfilePictureDir(), base64.URLEncoding.EncodeToString([]byte(userID))) + ".jpg"
}

func (u *userService) Delete(ctx context.Context, id, password string) error {
	if err := u.authService.VerifyPasswordByID(ctx, id, password); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	err := u.userRepo.Delete(ctx, id)
	if err != nil {
		return err
	}

	err = os.Remove(filepath.Join(config.ProfilePictureDir(), base64.StdEncoding.EncodeToString([]byte(id))) + ".jpg")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Errorf("Failed to delete profile picture of %s", id)
	}
	return nil
}
