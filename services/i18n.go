package services

import (
	"fmt"
	"strconv"
	"strings"
)

var translations = map[string]map[string]string{
	"en": {
		"submit":                          "Submit",
		"login":                           "Login",
		"signup":                          "Sign up",
		"logout":                          "Logout",
		"confirmEmail":                    "Confirm Email",
		"changeEmail":                     "Change Email",
		"confirm":                         "Confirm",
		"code":                            "Code",
		"createApp":                       "Create App",
		"name":                            "Name",
		"description":                     "Description",
		"website":                         "Website",
		"redirectURI":                     "Redirect URI",
		"create":                          "Create",
		"email":                           "Email",
		"password":                        "Password",
		"repeatPassword":                  "Repeat password",
		"createAccount":                   "Create account",
		"oauthConsent":                    "OAuth Consent",
		"loginWithHID":                    "Login with H-ID",
		"requestsPermissionTo":            "requests permission to",
		"deny":                            "Deny",
		"accept":                          "Accept",
		"profile":                         "Profile",
		"profilePicture":                  "Profile picture",
		"save":                            "Save",
		"update":                          "Update",
		"signInInstead":                   "Sign in instead",
		"dear":                            "Dear",
		"confirmEmailWith":                "You can confirm your email address using this code",
		"toChangeEmailClick":              "To update your email address click",
		"closedForm":                      "You closed the form?",
		"click":                           "Click",
		"here":                            "here",
		"didntCreateAccount":              "You didn't create this account?",
		"invalidCredentials":              "Invalid credentials",
		"scopesProfile":                   "View user and account information",
		"scopesEmail":                     "View your email address",
		"pressUpdateToUpload":             "Press 'Update' to upload your new profile picture.",
		"activate2FA":                     "Activate 2FA",
		"secretKey":                       "Secret key",
		"clickToCopy":                     "click to copy",
		"2fa":                             "2FA",
		"wasntYouIgnore":                  "If this wasn't you, you can safely ignore this email.",
		"emailChangeRequested":            "Please confirm the email change by clicking the link that has been sent to your new email address.",
		"emailChangeSuccess":              "Your email address has been successfully updated.",
		"emailChangeFailure":              "Your email address wasn't updated. Has your link expired?",
		"emailChangeFailureExists":        "Your email address wasn't updated because the new address is already in use by another account.",
		"newEmail":                        "New email address",
		"newEmailSameAsOld":               "Your new email address must be different from your old one.",
		"wrongPassword":                   "Wrong password.",
		"emailAlreadyInUse":               "This email address is already in use by another account.",
		"profilePictureTooLarge":          "Profile picture size must not exceed 10 MB",
		"profilePictureWrongFormat":       "Profile picture must be in JPEG, PNG or GIF format",
		"emailChanged":                    "Email Changed",
		"unexpectedEmailChange":           "You didn't change your email address for H-ID?",
		"emailChangedTo":                  "Your email address has been changed to:",
		"forgotPassword":                  "Forgot Password",
		"forgotPasswordLink":              "Forgot password",
		"resetLinkRequested":              "If this email address belongs to an account, a password reset link was sent to it.",
		"forgotPasswordTimeout":           "You have already requested a password reset link to this email address.",
		"toResetPasswordClick":            "To reset your password click",
		"resetPassword":                   "Reset Password",
		"newPassword":                     "New password",
		"expiredPasswordResetToken":       "Expired reset token.",
		"resetRecoveryCodesLink":          "reset recovery codes",
		"resetRecoveryCodes":              "Reset Recovery Codes",
		"reset":                           "Reset",
		"recoveryCodes":                   "Recovery Codes",
		"recoveryCodesExplanation":        "If you lose access to your authenticator app, you can use each one of these codes once instead of the OTP code to sign in. Store them securely!",
		"continue":                        "Continue",
		"download":                        "Download",
		"otpOrRecovery":                   "OTP or Recovery Code",
		"listApps":                        "Apps",
		"app":                             "App",
		"areYouSure":                      "Are you sure?",
		"areYouSureYouWantToDelete1":      "Are you sure you want to delete",
		"areYouSureYouWantToDelete2":      "?",
		"delete":                          "Delete",
		"cancel":                          "Cancel",
		"id":                              "ID",
		"created":                         "Created",
		"clientSecretWarning":             "This is the only time you will be shown the client secret. Copy it now and store it somewhere safe.",
		"done":                            "Done",
		"secret":                          "Secret",
		"managePasskeys":                  "manage passkeys",
		"passkeys":                        "Passkeys",
		"passkey":                         "Passkey",
		"createPasskey":                   "Create Passkey",
		"createdAt":                       "Created at",
		"usePasskey":                      "Use passkey",
		"or":                              "or",
		"invite":                          "Invite",
		"hello":                           "Hello",
		"invitation":                      "Invitation",
		"youHaveBeenInvitedToHID":         "You have been invited to H-ID",
		"createAccountFromInvitation":     "create account",
		"inviteOnlyInvalidToken":          "You need a valid invitation to create an account.",
		"invitationSuccess":               "Invitation sent.",
		"listUsers":                       "Users",
		"isAdmin":                         "Admin",
		"accountDeleted":                  "Account Deleted",
		"accountWithEmailDeletedByAdmin1": "Your account with the email address",
		"accountWithEmailDeletedByAdmin2": "has been deleted by an administrator",
		"confirmName":                     "Confirm name",
		"confirmNameWrong":                "Please type the name of the item you want to delete.",
		"resetOTP":                        "Reset OTP",
		"resetOTPLink":                    "reset OTP",
	},
	"de": {
		"submit":                          "Submit",
		"login":                           "Anmelden",
		"signup":                          "Registrieren",
		"logout":                          "Abmelden",
		"confirmEmail":                    "Email Bestätigen",
		"changeEmail":                     "Email Ändern",
		"confirm":                         "Bestätigen",
		"code":                            "Code",
		"createApp":                       "App Erstellen",
		"name":                            "Name",
		"description":                     "Beschreibung",
		"website":                         "Webseite",
		"redirectURI":                     "Umleitungs-URI",
		"create":                          "Erstellen",
		"email":                           "Email",
		"password":                        "Passwort",
		"repeatPassword":                  "Passwort wiederholen",
		"createAccount":                   "Account erstellen",
		"oauthConsent":                    "OAuth-Zustimmung",
		"loginWithHID":                    "Mit H-ID Anmelden",
		"requestsPermissionTo":            "bittet um folgende Berechtigungen",
		"deny":                            "Ablehnen",
		"accept":                          "Akzeptieren",
		"profile":                         "Nutzerprofil",
		"profilePicture":                  "Profilbild",
		"save":                            "Speichern",
		"update":                          "Aktualisieren",
		"signInInstead":                   "Stattdessen anmelden",
		"dear":                            "Hallo",
		"confirmEmailWith":                "Du kannst deine Email-Adresse mit diesem Code bestätigen",
		"toChangeEmailClick":              "Um deine Email zu ändern, klick",
		"closedForm":                      "Du hast die Seite geschlossen?",
		"click":                           "Klick",
		"here":                            "hier",
		"didntCreateAccount":              "You didn't create this account?",
		"invalidCredentials":              "Ungültige Zugangsdaten",
		"scopesProfile":                   "Profil und Account Informationen ansehen",
		"scopesEmail":                     "Email Adresse ansehen",
		"pressUpdateToUpload":             "Drücke 'Aktualisieren', um dein neues Profilbild hochzuladen.",
		"activate2FA":                     "2FA Aktivieren",
		"secretKey":                       "Geheimschlüssel",
		"clickToCopy":                     "antippen, um zu kopieren",
		"2fa":                             "2FA",
		"wasntYouIgnore":                  "Wenn du diese Email nicht angefragt hast, kannst du sie einfach ignorieren.",
		"emailChangeRequested":            "Bitte bestätige die neue Email-Änderung, indem du den Link öffnest, der an deine neue Email-Adresse gesendet wurde.",
		"emailChangeSuccess":              "Deine Email-Adresse wurde erfolgreich aktualisiert.",
		"emailChangeFailure":              "Deine Email-Adresse wurde nicht aktualisiert. Ist dein Link abgelaufen?",
		"emailChangeFailureExists":        "Deine Email-Adresse wurde nicht aktualisiert, weil die neue Adresse bereits für ein anderes Konto verwendet wird.",
		"newEmail":                        "Neue Email-Adresse",
		"newEmailSameAsOld":               "Die neue Email-Adresse muss anders als die alte Adresse sein.",
		"wrongPassword":                   "Falsches Passwort.",
		"emailAlreadyInUse":               "Diese Adresse wird bereits für einen anderen Account genutzt.",
		"profilePictureTooLarge":          "Profilbilder dürfen nicht größer als 10 MB sein.",
		"profilePictureWrongFormat":       "Profilbilder müssen im JPEG, PNG oder GIF Format sein.",
		"emailChanged":                    "Email Änderung",
		"unexpectedEmailChange":           "Du hast deine Email-Adresse bei H-ID nicht geändert?",
		"emailChangedTo":                  "Deine Email-Adresse wurde geändert zu:",
		"forgotPassword":                  "Passwort Vergessen",
		"forgotPasswordLink":              "Passwort vergessen",
		"resetLinkRequested":              "Falls diese Email-Adresse bei uns im System registriert ist, wurde ein Link zum Zurücksetzen des Passworts an sie gesendet.",
		"forgotPasswordTimeout":           "Du hast bereits einen Zurücksetzungslink an diese Adresse angefragt.",
		"toResetPasswordClick":            "Um dein Passwort zurückzusetzen, klick",
		"resetPassword":                   "Passwort Zurücksetzen",
		"newPassword":                     "Neues Passwort",
		"expiredPasswordResetToken":       "Abgelaufenes Zurücksetzungstoken.",
		"resetRecoveryCodesLink":          "Recovery Codes zurücksetzen",
		"resetRecoveryCodes":              "Recovery Codes Zurücksetzen",
		"reset":                           "Zurücksetzen",
		"recoveryCodes":                   "Recovery Codes",
		"recoveryCodesExplanation":        "Falls du Zugang zu deiner Authentifizierungs-App verlierst, kannst du jeden dieser Codes einmalig anstelle des OTP-Codes eingeben, um dich anzumelden. Bewahre sie sicher auf!",
		"continue":                        "Weiter",
		"download":                        "Herunterladen",
		"otpOrRecovery":                   "OTP oder Recovery Code",
		"listApps":                        "Apps",
		"app":                             "App",
		"areYouSure":                      "Sicher?",
		"areYouSureYouWantToDelete1":      "Bist du dir sicher, dass du",
		"areYouSureYouWantToDelete2":      " löschen willst?",
		"delete":                          "Löschen",
		"cancel":                          "Abbrechen",
		"id":                              "ID",
		"created":                         "Erstellt",
		"clientSecretWarning":             "Dies ist das einzige Mal, dass dir das Client Secret gezeigt wird. Kopiere es jetzt und verwahre es sicher.",
		"done":                            "Fertig",
		"secret":                          "Secret",
		"managePasskeys":                  "Passkeys verwalten",
		"passkeys":                        "Passkeys",
		"passkey":                         "Passkey",
		"createPasskey":                   "Passkey Erstellen",
		"createdAt":                       "Erstellt am",
		"usePasskey":                      "Passkey verwenden",
		"or":                              "oder",
		"invite":                          "Einladen",
		"hello":                           "Hallo",
		"invitation":                      "Einladung",
		"youHaveBeenInvitedToHID":         "Du wurdest zu H-ID eingeladen",
		"createAccountFromInvitation":     "Account erstellen",
		"inviteOnlyInvalidToken":          "Du brauchst eine valide Einladung, um einen Account zu erstellen.",
		"invitationSuccess":               "Einladung gesendet.",
		"listUsers":                       "Nutzer",
		"isAdmin":                         "Admin",
		"accountDeleted":                  "Account Gelöscht",
		"accountWithEmailDeletedByAdmin1": "Dein Account mit der Email-Adresse",
		"accountWithEmailDeletedByAdmin2": "wurde von einem Administrator gelöscht",
		"confirmName":                     "Name bestätigen",
		"confirmNameWrong":                "Bitte schreibe den Namen des Objektes, das du löschen möchtest.",
		"resetOTP":                        "OTP Zurücksetzen",
		"resetOTPLink":                    "OTP zurücksetzen",
	},
}

func MustTranslate(lang, key string) string {
	text, err := Translate(lang, key)
	if err != nil {
		panic(fmt.Sprintf("MustTranslate: %s", err))
	}
	return text
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
