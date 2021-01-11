package filters

import (
	c "appbackend/common"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
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
	amount := r.PostFormValue("amount")

	fmt.Println("NAZWA FILTRA:", name, ", IP:", ip, ", PORT:", port, ", ILOŚĆ POMIARÓW:", amount)

	switch name {
	case "trafficFilter":
		fmt.Println("Włączam `trafficFilter'")
		trafficResults, err := trafficFilter(name, amount)
		if err != nil {
			fmt.Println("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"trafficResults": trafficResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "pingerFilter":
		fmt.Println("Włączam 'pingerFilter'")

		pingerResults, err := pingerFilter(name, ip, amount)
		if err != nil {
			fmt.Println("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"pingerResults": pingerResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "tcpFilter":
		fmt.Println("Włączam 'tcpFilter'")
		tcpResults, err := tcpFilter(name, port, amount)
		if err != nil {
			fmt.Println("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"tcpResults": tcpResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)

	case "ipFilter":
		fmt.Println("Włączam 'ipFilter'")
		ipResults, err := ipFilter(name, ip, amount)
		if err != nil {
			fmt.Println("Wystąpił błąd przy generowaniu wyników", err)
			return
		}

		payload := map[string]interface{}{"ipResults": ipResults}
		wrapper := c.NewPayloadWrapper(0, payload)
		json.NewEncoder(w).Encode(wrapper)
	}
}

// Funkcja wykonuje polecenie 'tshark', które śledzi ogólny ruch w sieci
// Użytkownik podaje również ilość pomiarów do wykonania
func trafficFilter(name string, amount string) (string, error) {
	argument := "-c" + amount

	cmd := exec.Command("E:/Wireshark/tshark", argument)
	cmdOutput, err := cmd.Output()
	if err != nil {
		fmt.Println("Niepowodzenie podczas uruchomienia komendy 'tshark'", err)
		return "", err
	}

	fmt.Println("Wynik komendy 'tshark", string(cmdOutput))
	return string(cmdOutput), nil
}

// Funkcja wykonuje polecenie 'ping' na adres wskazany przez użytkownika
// Użytkownik podaje rownież ilość serii pomiarowych
func pingerFilter(name string, ip string, amount string) ([]string, error) {
	amountInt, err := strconv.Atoi(amount)
	if err != nil {
		fmt.Println("Wystąpił błąd podczas konwersji ze string na int")
		return nil, err
	}

	var results []string
	for i := 0; i < amountInt; i++ {
		cmd, err := exec.Command("ping", ip).Output()
		if err != nil {
			fmt.Println("Niepowodzenie podczas uruchomienia komendy 'ping'")
			return nil, err
		}
		fmt.Println("Wynik komendy 'ping'", string(cmd))
		results = append(results, string(cmd))
	}
	return results, nil
}

// Funkcja wykonuje polecenie 'tcp.port'
// Użytkownik podaje port, którego ruch chce śledzić oraz liczbę pomiarów do wykonania
func tcpFilter(name string, port string, amount string) (string, error) {
	argument := "-d tcp.port==" + port + " http -c" + amount

	cmd := exec.Command("E:/Wireshark/tshark", argument)
	cmdOutput, err := cmd.Output()
	if err != nil {
		fmt.Println("Niepowodzenie podczas uruchomienia komendy 'tcp.port'")
		return "", err
	}

	fmt.Println("Wynik komendy 'tcp.port", string(cmdOutput))
	return string(cmdOutput), nil
}

// Funkcja wykonuje polecenie 'tshark', które śledzi śledzi ogólny ruch w sieci
// Użytkownik podaje adres IP, którego ruch chce śledzić oraz liczbę pomiarów do wykonania
func ipFilter(name string, ip string, amount string) (string, error) {
	argument := "-c" + amount + " host " + ip

	cmd := exec.Command("E:/Wireshark/tshark", argument)
	cmdOutput, err := cmd.Output()
	if err != nil {
		fmt.Println("Niepowodzenie podczas uruchomienia komendy 'tshark'")
		return "", err
	}

	fmt.Println("Wynik komendy 'tshark'", string(cmdOutput))
	return string(cmdOutput), nil
}
