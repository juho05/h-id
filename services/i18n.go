package services

import (
	"fmt"
	"strconv"
	"strings"
)

var translations = map[string]map[string]string{
	"en": {
		"login":                "Login",
		"signup":               "Sign up",
		"logout":               "Logout",
		"confirmEmail":         "Confirm Email",
		"confirm":              "Confirm",
		"code":                 "Code",
		"createApp":            "Create App",
		"name":                 "Name",
		"description":          "Description",
		"website":              "Website",
		"redirectURI":          "Redirect URI",
		"create":               "Create",
		"email":                "Email",
		"password":             "Password",
		"repeatPassword":       "Repeat password",
		"createAccount":        "Create account",
		"oauthConsent":         "OAuth Consent",
		"loginWithHID":         "Login with H-ID",
		"requestsPermissionTo": "requests permission to",
		"deny":                 "Deny",
		"accept":               "Accept",
		"profile":              "Profile",
		"profilePicture":       "Profile picture",
		"save":                 "Save",
		"signInInstead":        "Sign in instead",
		"dear":                 "Dear",
		"confirmEmailWith":     "You can confirm your email address using this code",
		"closedForm":           "You closed the form?",
		"click":                "Click",
		"here":                 "here",
		"didntCreateAccount":   "You didn't create this account?",
		"invalidCredentials":   "Invalid credentials",
		"scopesProfile":        "View user and account information",
		"scopesEmail":          "View your email address",
		"pressSaveToUpload":    "Press 'save' to update your profile picture.",
	},
	"de": {
		"login":                "Anmelden",
		"signup":               "Registrieren",
		"logout":               "Abmelden",
		"confirmEmail":         "Email Bestätigen",
		"confirm":              "Bestätigen",
		"code":                 "Code",
		"createApp":            "App Erstellen",
		"name":                 "Name",
		"description":          "Beschreibung",
		"website":              "Webseite",
		"redirectURI":          "Umleitungs-URI",
		"create":               "Erstellen",
		"email":                "Email",
		"password":             "Passwort",
		"repeatPassword":       "Passwort wiederholen",
		"createAccount":        "Account erstellen",
		"oauthConsent":         "OAuth-Zustimmung",
		"loginWithHID":         "Mit H-ID Anmelden",
		"requestsPermissionTo": "bittet um folgende Berechtigungen",
		"deny":                 "Ablehnen",
		"accept":               "Akzeptieren",
		"profile":              "Nutzerprofil",
		"profilePicture":       "Profilbild",
		"save":                 "Speichern",
		"signInInstead":        "Stattdessen anmelden",
		"dear":                 "Hallo",
		"invalidCredentials":   "Ungültige Zugangsdaten",
		"scopesProfile":        "Profil und Account Informationen ansehen",
		"scopesEmail":          "Email Adresse ansehen",
		"pressSaveToUpload":    "Drück 'speichern', um dein Profilbild zu aktualisieren.",
	},
}

func Translate(lang, key string) (string, error) {
	t, ok := translations[lang]
	if !ok {
		t = translations["en"]
	}
	v, ok := t[key]
	if !ok {
		v, ok = translations["en"][key]
		if !ok {
			return "", fmt.Errorf("unknown key: %s", key)
		}
	}
	return v, nil
}

func GetLanguageFromAcceptLanguageHeader(headerValue string) string {
	lang := "en"
	quality := float64(0)

	strs := strings.Split(headerValue, ",")
	for _, s := range strs {
		parts := strings.Split(s, ";")
		q := float64(1)
		if len(parts) > 1 {
			qStr := parts[1]
			qStr = strings.ReplaceAll(qStr, "q", "")
			qStr = strings.ReplaceAll(qStr, "=", "")
			qStr = strings.TrimSpace(qStr)
			_, err := strconv.ParseFloat(qStr, 64)
			if err == nil {
				q, _ = strconv.ParseFloat(qStr, 64)
			}
		}

		if q > quality {
			l := strings.TrimSpace(strings.Split(parts[0], "-")[0])
			if _, ok := translations[l]; ok {
				lang = l
				quality = q
			}
		}
	}

	return lang
}
