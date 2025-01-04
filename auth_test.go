package main

import (
	"fmt"
	"log"
	"testing"
	"time"

	internal "github.com/TKyleB/BOOTDEV_Chripy/internal/auth"
	"github.com/google/uuid"
)

func TestCheckPasswordHash(t *testing.T) {
	inputs := []struct {
		Password string
		Hash     string
	}{
		{Password: "Kyle", Hash: ""},
		{Password: "This is a password!", Hash: ""},
	}

	for i, input := range inputs {
		hashedPassword, err := internal.HashPassword(input.Password)
		if err != nil {
			log.Printf("%v", err)
		}
		inputs[i].Hash = hashedPassword
	}
	for _, input := range inputs {
		fmt.Printf("%s, %s", input.Password, input.Hash)
		err := internal.CheckPasswordHash(input.Password, input.Hash)
		if err != nil {
			t.Errorf("Hashing incorrect: %v", err)
		}
	}

}

func TestValidateJWT(t *testing.T) {
	inputId, _ := uuid.NewRandom()
	inputToken, _ := internal.MakeJWT(inputId, "secret", time.Hour)
	output, _ := internal.ValidateJWT(inputToken, "secret")
	if output != inputId {
		t.Fail()
	}
}
