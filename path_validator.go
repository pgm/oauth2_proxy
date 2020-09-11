package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
)

type PathValidator interface {
	RequiresValidation(username string) bool
	IsValid(username string, path string) bool
}

type UserGroupPathValidator struct {
	usernames    map[string]string
	allowedPaths []*regexp.Regexp
}

func NewUserGroupPathValidator(usernames []string, allowedPaths []string) (*UserGroupPathValidator, error) {
	usernameMap := make(map[string]string)
	allowedPathsRegExps := make([]*regexp.Regexp, len(allowedPaths))

	for _, username := range usernames {
		usernameMap[username] = username
	}

	for i, allowedPath := range allowedPaths {
		p, err := regexp.Compile("^" + allowedPath)
		if err != nil {
			return nil, err
		}
		// log.Printf("Compiled '%v' -> '%v'", allowedPath, p)

		allowedPathsRegExps[i] = p
	}

	return &UserGroupPathValidator{usernameMap, allowedPathsRegExps}, nil
}

func (v *UserGroupPathValidator) IsValid(username string, path string) bool {
	// next check to see if this is a name in this group
	_, ok := v.usernames[username]
	// log.Printf("IsValid(%s, %s) {containsUsername=%v, paths=%v}", username, path, ok, v.allowedPaths)
	if !ok {
		return false
	}

	// and the path is allowed
	for _, allowedPath := range v.allowedPaths {
		if allowedPath.MatchString(path) {
			// log.Printf("match: %v == %v", allowedPath, path)
			return true
		}
	}

	return false
}

func (v *UserGroupPathValidator) RequiresValidation(username string) bool {
	_, ok := v.usernames[username]
	if !ok {
		return false
	}
	return true
}

type CompositePathValidator struct {
	isUsernameWhitelisted func(string) bool
	Validators            []PathValidator
}

func (v *CompositePathValidator) IsValid(username string, path string) bool {
	// check the global list of allowed names first
	log.Printf("IsValid(%s, %s)", username, path)
	if v.isUsernameWhitelisted(username) {
		log.Printf("isUsernameWhitelisted -> true")
		return true
	}
	for _, v := range v.Validators {
		if v.IsValid(username, path) {
			return true
		}
	}

	log.Printf("isUsernameWhitelisted -> false")
	return false
}

func (v *CompositePathValidator) RequiresValidation(username string) bool {
	for _, v := range v.Validators {
		if v.RequiresValidation(username) {
			return true
		}
	}

	return false
}

func parseUserPathWhitelistFromReader(fp io.Reader, filename string, isUsernameWhitelisted func(string) bool) (PathValidator, error) {
	type Group struct {
		Name      string   `json:"name"`
		Paths     []string `json:"paths"`
		Usernames []string `json:"usernames"`
	}
	type Config struct {
		Groups []*Group `json:"groups"`
	}

	dec := json.NewDecoder(fp)

	var config Config
	err := dec.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("Could not parse %s: %s", filename, err)
	}

	validators := make([]PathValidator, len(config.Groups))
	for i, g := range config.Groups {
		v, err := NewUserGroupPathValidator(g.Usernames, g.Paths)
		if err != nil {
			return nil, err
		}
		validators[i] = v
	}

	return &CompositePathValidator{isUsernameWhitelisted: isUsernameWhitelisted, Validators: validators}, nil
}

func parseUserPathWhitelist(filename string, isUsernameWhitelisted func(string) bool) (PathValidator, error) {
	if filename == "" {
		// if no file is provided, return a validator that only does the username verification
		return &CompositePathValidator{isUsernameWhitelisted: isUsernameWhitelisted, Validators: nil}, nil
	}

	fp, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Could not open %s: %s", filename, err)
	}
	defer fp.Close()

	return parseUserPathWhitelistFromReader(fp, filename, isUsernameWhitelisted)
}

// func (v *)
