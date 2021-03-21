package filters

import (
	c "appbackend/common"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// ReadFilterParams odczytuje rodzaj filtru wybranego przez użytkownika oraz niezbędne parametry
func ReadFilterParams(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	ip := r.PostFormValue("ip")
	protocole := r.PostFormValue("protocole")
	networkInterface := r.PostFormValue("interface")
	amount := r.PostFormValue("amount")

	switch name {
	case "trafficFilter":

		trafficResults, err := trafficFilter(name, amount, networkInterface)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"trafficResults": trafficResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "pingerFilter":
		pingerResults, err := pingerFilter(name, ip, amount)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"pingerResults": pingerResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "protocoleFilter":
		protocoleResults, err := protocoleFilter(name, amount, networkInterface, protocole)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"protocoleResults": protocoleResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "ipFilter":
		ipResults, err := ipFilter(name, ip, amount, networkInterface)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"ipResults": ipResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "addressPorts":
		addressResults, err := addressPortsFilter(ip)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"addressPortsResults": addressResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "connectedDevicesPorts":
		connectedDevicesResults, err := connectedDevicesPortsFilter()
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"connectedDevicesPortsResults": connectedDevicesResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "traceRoute":
		traceRouteResults, err := traceRouteFilter(ip)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"traceRouteResults": traceRouteResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "topPortsBasic":
		topPortsBasicResults, err := topPortsBasicFilter(ip, amount)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"topPortsBasicResults": topPortsBasicResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "topPortsAdvanced":
		topPortsAdvancedResults, err := topPortsAdvancedFilter(ip, amount)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"topPortsAdvancedResults": topPortsAdvancedResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)
	}

}

// Funkcja wykonuje polecenie 'tshark', które śledzi ogólny ruch w sieci
// Użytkownik podaje ilość pomiarów do wykonania
func trafficFilter(name string, amount string, networkInterface string) (string, error) {
	log.WithFields(log.Fields{
		"ILOŚĆ POMIARÓW":      amount,
		"SKANOWANY INTERFEJS": networkInterface,
		"NAZWA FILTRA":        name,
	}).Info()

	// sumArgument:="-z io, stat, 0, SUM(frame.len)frame.len"
	cmd := exec.Command("tshark", "-i", networkInterface, "-c", amount)

	cmdOutput, err := cmd.Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'tshark'", err)
		return "", err
	}

	return string(cmdOutput), nil
}

// Funkcja wykonuje polecenie 'ping' na adres wskazany przez użytkownika
// Użytkownik podaje rownież ilość serii pomiarowych
func pingerFilter(name string, ip string, amount string) ([]string, error) {
	log.WithFields(log.Fields{
		"ILOŚĆ POMIARÓW": amount,
		"ADRES IP":       ip,
		"NAZWA FILTRA":   name,
	}).Info()

	var results []string

	amountInt, err := strconv.Atoi(amount)
	if err != nil {
		log.Error("Wystąpił błąd podczas konwersji ze string na int")
		return nil, err
	}

	for i := 0; i < amountInt; i++ {
		cmd, err := exec.Command("HRping", ip).Output()
		if err != nil {
			log.Error("Niepowodzenie podczas uruchomienia komendy 'ping'")
			return nil, err
		}
		results = append(results, string(cmd))
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}
	return results, nil
}

// Użytkownik podaje protokół, którego ruch chce śledzić oraz liczbę pomiarów do wykonania
func protocoleFilter(name string, amount string, networkInterface string, protocole string) (string, error) {
	log.WithFields(log.Fields{
		"ILOŚĆ POMIARÓW":      amount,
		"PROTOKÓŁ":            protocole,
		"SKANOWANY INTERFEJS": networkInterface,
		"NAZWA FILTRA":        name,
	}).Info()

	// sumArgument:="-z io, stat, 0, SUM(frame.len)frame.len"
	cmd := exec.Command("tshark", "-i", networkInterface, "-f", protocole, "-c", amount)
	cmdOutput, err := cmd.Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy")
		return "", err
	}

	return string(cmdOutput), nil
}

// Funkcja wykonuje polecenie 'tshark', które śledzi śledzi ogólny ruch w sieci
// Użytkownik podaje adres IP, którego ruch chce śledzić oraz liczbę pomiarów do wykonania
func ipFilter(name string, ip string, amount string, networkInterface string) (string, error) {
	log.WithFields(log.Fields{
		"ILOŚĆ POMIARÓW":      amount,
		"IP":                  ip,
		"SKANOWANY INTERFEJS": networkInterface,
		"NAZWA FILTRA":        name,
	}).Info()

	cmd := exec.Command("tshark", "-i", networkInterface, "-c", amount, "host", ip)
	cmdOutput, err := cmd.Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'tshark'")
		return "", err
	}

	return string(cmdOutput), nil
}

func addressPortsFilter(ip string) (string, error) {
	log.Info("IP/HOST:", ip)

	cmd, err := exec.Command("nmap", ip).Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'nmap'")
		return "", err
	}

	return string(cmd), nil
}

func connectedDevicesPortsFilter() (string, error) {
	log.Info("Connected devices ports filter enabled")

	cmd, err := exec.Command("nmap", "-sV", "-p", "22,443", "192.168.1.0/24", "-open").Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'nmap'")
		return "", err
	}

	return string(cmd), nil
}

func traceRouteFilter(ip string) (string, error) {
	log.Info("IP/HOST:", ip)

	cmd, err := exec.Command("nmap", "-sn", "--traceroute ", ip).Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'nmap'")
		return "", err
	}

	return string(cmd), nil
}

func topPortsBasicFilter(ip string, amount string) (string, error) {
	log.Info("Top ", amount, " ports for ", ip, " with basic params enabled")

	cmd, err := exec.Command("nmap", "--top-ports", amount, ip).Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'nmap'")
		return "", err
	}

	return string(cmd), nil
}

func topPortsAdvancedFilter(ip string, amount string) (string, error) {
	log.Info("Top ", amount, " ports for ", ip, " with advanced params enabled")

	cmd, err := exec.Command("nmap", "-vv", "-O", "-P0", "-sTUV", "--top-ports", amount, ip).Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'nmap'")
		return "", err
	}

	return string(cmd), nil
}
