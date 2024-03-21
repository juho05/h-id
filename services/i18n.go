package services

import (
	"fmt"
	"strconv"
	"strings"
)

var translations = map[string]map[string]string{
	"en": {
		"login":                    "Login",
		"signup":                   "Sign up",
		"logout":                   "Logout",
		"confirmEmail":             "Confirm Email",
		"changeEmail":              "Change Email",
		"confirm":                  "Confirm",
		"code":                     "Code",
		"createApp":                "Create App",
		"name":                     "Name",
		"description":              "Description",
		"website":                  "Website",
		"redirectURI":              "Redirect URI",
		"create":                   "Create",
		"email":                    "Email",
		"password":                 "Password",
		"repeatPassword":           "Repeat password",
		"createAccount":            "Create account",
		"oauthConsent":             "OAuth Consent",
		"loginWithHID":             "Login with H-ID",
		"requestsPermissionTo":     "requests permission to",
		"deny":                     "Deny",
		"accept":                   "Accept",
		"profile":                  "Profile",
		"profilePicture":           "Profile picture",
		"save":                     "Save",
		"update":                   "Update",
		"signInInstead":            "Sign in instead",
		"dear":                     "Dear",
		"confirmEmailWith":         "You can confirm your email address using this code",
		"toChangeEmailClick":       "To update your email address click",
		"closedForm":               "You closed the form?",
		"click":                    "Click",
		"here":                     "here",
		"didntCreateAccount":       "You didn't create this account?",
		"invalidCredentials":       "Invalid credentials",
		"scopesProfile":            "View user and account information",
		"scopesEmail":              "View your email address",
		"pressUpdateToUpload":      "Press 'Update' to upload your new profile picture.",
		"activate2FA":              "Activate 2FA",
		"secretKey":                "Secret key",
		"2fa":                      "2FA",
		"wasntYouIgnore":           "If this wasn't you, you can safely ignore this email.",
		"emailChangeRequested":     "Please confirm the email change by clicking the link that has been sent to your new email address.",
		"emailChangeSuccess":       "Your email address has been successfully updated.",
		"emailChangeFailure":       "Your email address wasn't updated. Has your link expired?",
		"emailChangeFailureExists": "Your email address wasn't updated because the new address is already in use by another account.",
	},
	"de": {
		"login":                    "Anmelden",
		"signup":                   "Registrieren",
		"logout":                   "Abmelden",
		"confirmEmail":             "Email Bestätigen",
		"changeEmail":              "Email Ändern",
		"confirm":                  "Bestätigen",
		"code":                     "Code",
		"createApp":                "App Erstellen",
		"name":                     "Name",
		"description":              "Beschreibung",
		"website":                  "Webseite",
		"redirectURI":              "Umleitungs-URI",
		"create":                   "Erstellen",
		"email":                    "Email",
		"password":                 "Passwort",
		"repeatPassword":           "Passwort wiederholen",
		"createAccount":            "Account erstellen",
		"oauthConsent":             "OAuth-Zustimmung",
		"loginWithHID":             "Mit H-ID Anmelden",
		"requestsPermissionTo":     "bittet um folgende Berechtigungen",
		"deny":                     "Ablehnen",
		"accept":                   "Akzeptieren",
		"profile":                  "Nutzerprofil",
		"profilePicture":           "Profilbild",
		"save":                     "Speichern",
		"update":                   "Aktualisieren",
		"signInInstead":            "Stattdessen anmelden",
		"dear":                     "Hallo",
		"confirmEmailWith":         "Du kannst deine Email-Adresse mit diesem Code bestätigen",
		"toChangeEmailClick":       "Um deine Email zu ändern, klick",
		"closedForm":               "Du hast die Seite geschlossen?",
		"click":                    "Klick",
		"here":                     "hier",
		"didntCreateAccount":       "You didn't create this account?",
		"invalidCredentials":       "Ungültige Zugangsdaten",
		"scopesProfile":            "Profil und Account Informationen ansehen",
		"scopesEmail":              "Email Adresse ansehen",
		"pressUpdateToUpload":      "Drücke 'Aktualisieren', um dein neues Profilbild hochzuladen.",
		"activate2FA":              "2FA Aktivieren",
		"secretKey":                "Geheimschlüssel",
		"2fa":                      "2FA",
		"wasntYouIgnore":           "Wenn du diese Email nicht angefragt hast, kannst du sie einfach ignorieren.",
		"emailChangeRequested":     "Bitte bestätige die neue Email-Änderung, indem du den Link öffnest, der an deine neue Email-Adresse gesendet wurde.",
		"emailChangeSuccess":       "Deine Email-Adresse wurde erfolgreich aktualisiert.",
		"emailChangeFailure":       "Deine Email-Adresse wurde nicht aktualisiert. Ist dein Link abgelaufen?",
		"emailChangeFailureExists": "Deine Email-Adresse wurde nicht aktualisiert, weil die neue Adresse bereits für ein anderes Konto verwendet wird.",
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
