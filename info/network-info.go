package info

import (
	c "appbackend/common"
	"encoding/json"
	"net/http"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

//GetSystemInfo zwraca podstawowe informacje na temat połączenia sieciowego
func GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	ipConfigResults, err := readSystemInfo()
	if err != nil {
		log.Error("Wystąpił błąd przy generowaniu wyników przez 'readSystemInfo'", err)
		return
	}

	nmapResults, err := nmapInfo()
	if err != nil {
		log.Error("Wystąpił błąd przy generowaniu wyników przez 'nmapInfo'", err)
		return
	}

	interfacesResults, err := findAllInterfaces()
	if err != nil {
		log.Error("Wystąpił błąd przy generowaniu wyników przez 'findAllInterfaces'", err)
		return
	}

	log.Info("Pobrano podstawowe informacje o połączeniu")
	payload := map[string]interface{}{"configResults": ipConfigResults, "nmapResults": nmapResults, "interfacesResults": interfacesResults}
	wrapper := c.NewPayloadWrapper(0, payload)
	json.NewEncoder(w).Encode(wrapper)
}

// Funkcja wykonuje polecenie 'ipconfig', które podaje podstawowe informacje o połączeniu
func readSystemInfo() (string, error) {
	cmd := exec.Command("ipconfig")
	cmdOutput, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(cmdOutput), nil
}

// Funkja wykonuje komendę 'nmap' na wybrany host
func nmapInfo() (string, error) {
	argument := "192.168.0.1"

	cmd, err := exec.Command("nmap", argument).Output()
	if err != nil {
		return "", err
	}

	return string(cmd), nil
}

// Funkcja zwraca dostępne interfejsy sieciowe
func findAllInterfaces() (string, error) {
	cmd, err := exec.Command("tshark", "--list-interfaces").Output()
	if err != nil {
		return "", err
	}

	return string(cmd), nil
}
