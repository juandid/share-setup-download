package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Regex für Benutzernamen: nur erlaubte Zeichen, 3-20 Zeichen lang
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9!.&*\-]{3,20}$`)
	// Regex für Passwort: gleiche erlaubte Zeichen, 8-20 Zeichen lang
	passwordRegex := regexp.MustCompile(`^[a-zA-Z0-9!.&*\-]{8,20}$`)

	reader := bufio.NewReader(os.Stdin)

	// 1. Benutzernamen einlesen und validieren
	var username string
	for {
		fmt.Print("Bitte Benutzernamen eingeben (3-20 Zeichen, erlaubt: a-z, A-Z, 0-9, !, -, ., &, *): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Fehler beim Einlesen:", err)
			continue
		}
		username = strings.TrimSpace(input)
		if usernameRegex.MatchString(username) {
			break
		}
		fmt.Println("Ungültiger Benutzername. Bitte erneut versuchen.")
	}

	// 2. Passwort einlesen und validieren
	var password string
	for {
		fmt.Print("Bitte Passwort eingeben (8-20 Zeichen, erlaubt: a-z, A-Z, 0-9, !, -, ., &, *): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Fehler beim Einlesen:", err)
			continue
		}
		password = strings.TrimSpace(input)
		if passwordRegex.MatchString(password) {
			break
		}
		fmt.Println("Ungültiges Passwort. Bitte erneut versuchen.")
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

	fmt.Println("Der Hash wurde erfolgreich erstellt und in", hashFilePath, "gespeichert.")
}
