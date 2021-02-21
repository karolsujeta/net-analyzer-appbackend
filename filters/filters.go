package filters

import (
	c "appbackend/common"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// Filter reprezentuje strukturę parametrów filtra
type Filter struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Amount string `json:"amount"`
}

// ReadFilterParams odczytuje rodzaj filtru wybranego przez użytkownika oraz niezbędne parametry
func ReadFilterParams(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	ip := r.PostFormValue("ip")
	port := r.PostFormValue("port")
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

	case "tcpFilter":
		tcpResults, err := tcpFilter(name, port, amount, networkInterface, protocole)
		if err != nil {
			log.Error("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"tcpResults": tcpResults}
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

	saveTxt, err := os.Create("pinger_results.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer saveTxt.Close()

	for i := 0; i < amountInt; i++ {
		cmd, err := exec.Command("ping", ip).Output()
		if err != nil {
			log.Error("Niepowodzenie podczas uruchomienia komendy 'ping'")
			return nil, err
		}
		// fmt.Println("Wynik komendy 'ping'", string(cmd))
		results = append(results, string(cmd))
		saveTxt.WriteString(string(cmd))
		if err != nil {
			fmt.Println(err)
			saveTxt.Close()
			return nil, err
		}
	}
	return results, nil
}

// Funkcja wykonuje polecenie 'tcp.port'
// Użytkownik podaje port, którego ruch chce śledzić oraz liczbę pomiarów do wykonania
func tcpFilter(name string, port string, amount string, networkInterface string, protocole string) (string, error) {
	log.WithFields(log.Fields{
		"ILOŚĆ POMIARÓW":      amount,
		"PROTOKÓŁ":            protocole,
		"PORT":                port,
		"SKANOWANY INTERFEJS": networkInterface,
		"NAZWA FILTRA":        name,
	}).Info()

	cmd := exec.Command("tshark", "-i", networkInterface, "-d", "tcp.port=="+port+","+protocole, "-c", amount)
	cmdOutput, err := cmd.Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'tcp.port'")
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

	cmd, err := exec.Command("nmap", "-sV", "-p", "22,443", "192.168.0.0/24", "-open").Output()
	if err != nil {
		log.Error("Niepowodzenie podczas uruchomienia komendy 'nmap'")
		return "", err
	}

	return string(cmd), nil
}

func traceRouteFilter(ip string) (string, error) {
	log.Info("IP/HOST:", ip)

	cmd, err := exec.Command("nmap", "-vv", "-n", "-sn", "-PE", "-T4", "--packet-trace", ip).Output()
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
