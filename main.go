package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// generateSuggestionPassword erzeugt einen zufälligen, 10 Zeichen langen Passwortvorschlag,
// der mindestens einen Kleinbuchstaben, einen Großbuchstaben und ein Sonderzeichen enthält.
func generateSuggestionPassword() string {
	lowerChars := "abcdefghijklmnopqrstuvwxyz"
	upperChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	specialChars := "!-.&*"
	// Gesamter erlaubter Zeichenvorrat
	allowedChars := lowerChars + upperChars + digits + specialChars

	length := 10
	passwordRunes := make([]rune, length)

	// Garantiert mindestens einen Kleinbuchstaben
	passwordRunes[0] = rune(lowerChars[randomIndex(len(lowerChars))])
	// Garantiert mindestens einen Großbuchstaben
	passwordRunes[1] = rune(upperChars[randomIndex(len(upperChars))])
	// Garantiert mindestens ein Sonderzeichen
	passwordRunes[2] = rune(specialChars[randomIndex(len(specialChars))])

	// Fülle die restlichen Positionen zufällig aus dem gesamten Zeichenvorrat
	for i := 3; i < length; i++ {
		passwordRunes[i] = rune(allowedChars[randomIndex(len(allowedChars))])
	}

	// Zufälliges Mischen der Zeichen (Fisher-Yates-Algorithmus)
	shuffleRunes(passwordRunes)

	return string(passwordRunes)
}

// randomIndex liefert einen zufälligen Index im Bereich [0, max) unter Verwendung von crypto/rand.
func randomIndex(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}

// shuffleRunes mischt ein Slice von runes zufällig.
func shuffleRunes(runes []rune) {
	for i := len(runes) - 1; i > 0; i-- {
		j := randomIndex(i + 1)
		runes[i], runes[j] = runes[j], runes[i]
	}
}

func main() {
	// Regex für Benutzernamen: nur erlaubte Zeichen, 3-20 Zeichen lang
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9!.&*\-]{3,20}$`)
	// Regex für Passwort: gleiche erlaubte Zeichen, 8-20 Zeichen lang
	passwordRegex := regexp.MustCompile(`^[a-zA-Z0-9!.&*\-]{8,20}$`)
	// Separate Regex-Ausdrücke für die Mindestanforderungen
	hasLower := regexp.MustCompile(`[a-z]`)
	hasUpper := regexp.MustCompile(`[A-Z]`)
	hasSpecial := regexp.MustCompile(`[!.&*\-]`)
	reader := bufio.NewReader(os.Stdin)

	// 1. Benutzernamen einlesen und validieren
	var username string
	for {
		fmt.Print("Bitte Benutzernamen eingeben (3-20 Zeichen): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Fehler beim Einlesen:", err)
			continue
		}
		username = strings.TrimSpace(input)
		if usernameRegex.MatchString(username) {
			break
		}
		fmt.Println("Ungültiger Benutzername. 3-20 Zeichen bestehend aus: a-z, A-Z, 0-9, !, -, ., &, *")
	}

	// Erzeuge einen Passwort-Vorschlag
	suggestion := generateSuggestionPassword()

	// 2. Passwort einlesen und validieren
	var password string
	for {
		fmt.Printf("Bitte Passwort eingeben (8-20 Zeichen) oder bestätige den Vorschlag mit Enter [%s]: ", suggestion)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Fehler beim Einlesen:", err)
			continue
		}
		password = strings.TrimSpace(input)

		// Drückt der Benutzer gleich Enter, wird der Vorschlag verwendet.
		if password == "" {
			password = suggestion
		}

		if !passwordRegex.MatchString(password) {
			fmt.Println("Ungültiges Passwort. 8-20 Zeichen bestehend aus: a-z, A-Z, 0-9, !, -, ., &, *")
			continue
		}

		// Mindestens ein Kleinbuchstabe
		if !hasLower.MatchString(password) {
			fmt.Println("Das Passwort muss mindestens einen Kleinbuchstaben enthalten.")
			continue
		}

		// Mindestens ein Großbuchstabe
		if !hasUpper.MatchString(password) {
			fmt.Println("Das Passwort muss mindestens einen Großbuchstaben enthalten.")
			continue
		}

		// Mindestens ein Sonderzeichen
		if !hasSpecial.MatchString(password) {
			fmt.Println("Das Passwort muss mindestens ein Sonderzeichen enthalten (erlaubt: !, -, ., &, *).")
			continue
		}
		break
	}

	// 3. Erstelle den Unterordner im download-Verzeichnis
	// Ermitteln des aktuellen Arbeitsverzeichnisses
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Fehler beim Ermitteln des aktuellen Arbeitsverzeichnisses:", err)
		return
	}

	// Pfad: <aktuelles Verzeichnis>/download/<Benutzername>
	downloadDir := filepath.Join(cwd, "download", username)

	// Erstelle alle notwendigen Ordner (download und Benutzerordner)
	err = os.MkdirAll(downloadDir, 0755)
	if err != nil {
		fmt.Println("Fehler beim Erstellen des Verzeichnisses:", err)
		return
	}

	// 4. Passwort-Hash erzeugen (bcrypt wie in PHP's password_hash)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Fehler beim Erzeugen des Passwort-Hashs:", err)
		return
	}

	// Datei hash.txt im Unterordner erstellen und den Hash hineinschreiben
	hashFilePath := filepath.Join(downloadDir, "hash.txt")
	err = os.WriteFile(hashFilePath, hash, 0644)
	if err != nil {
		fmt.Println("Fehler beim Schreiben der Datei hash.txt:", err)
		return
	}
	fmt.Print("\n")
	fmt.Println("Der Hash wurde erfolgreich erstellt und in", hashFilePath, "gespeichert.")
	fmt.Printf("Dateidownload auf https://share.juandid.com/login.php?username=%s", username)
	fmt.Print("\n")
	fmt.Printf("Das Passwort lautet: '%s'", password)
	fmt.Print("\n")

}
