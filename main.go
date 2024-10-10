package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/go-ping/ping"
	_ "github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"github.com/likexian/whois"
)

type ScanResult struct {
	Ports  string
	Target string
	Result string
}

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.File("templates/index.html")
	})

	e.GET("/about", func(c echo.Context) error {
		return c.File("templates/about.html")
	})

	e.GET("/services", func(c echo.Context) error {
		return c.File("templates/services.html")
	})

	// Routing Nmap Tool
	e.GET("/nmap", func(c echo.Context) error {
		return c.File("templates/nmap/nmap.html")
	})

	// Routing untuk generate Nmap
	e.POST("/scan", func(c echo.Context) error {
		target := c.FormValue("target")
		ports := "1-20000"

		fmt.Printf("Scanning ports %s on %s...\n", ports, target)

		// Tambahkan -T4 atau -T5 untuk intensitas scanning yang lebih tinggi
		cmd := exec.Command("nmap", "-T5", "-Pn", "-p", ports, target)

		// Nonaktifkan resolusi DNS dan host discovery untuk mempercepat
		// tambahkan -n dan -Pn
		// cmd := exec.Command("nmap", "-T4", "-n", "-Pn", "-p", ports, target)

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Error executing nmap command: %s", err)
		}

		result := strings.TrimSpace(string(output))

		data := ScanResult{
			Ports:  ports,
			Target: target,
			Result: result,
		}

		tmpl := template.Must(template.ParseFiles("templates/nmap/nmap_result.html"))

		return c.HTML(http.StatusOK, renderTemplate(tmpl, data))
	})

	// Routing Whois Tool
	e.GET("/whois", func(c echo.Context) error {
		return c.File("templates/whois/whois.html")
	})

	// Routing untuk meng-handle permintaan Whois
	e.POST("/whois", func(c echo.Context) error {
		domain := c.FormValue("domain")

		whoisResult, err := whois.Whois(domain)
		if err != nil {
			if strings.Contains(err.Error(), "No such domain") {

				return c.String(http.StatusNotFound, "Domain does not exist")
			} else {
				log.Fatalf("Error retrieving whois information: %s", err)
			}
		}

		result := strings.TrimSpace(whoisResult)

		data := ScanResult{
			Result: result,
		}

		tmpl := template.Must(template.ParseFiles("templates/whois/whois_result.html"))

		return c.HTML(http.StatusOK, renderTemplate(tmpl, data))
	})

	// Routing Ping ICMP Tool
	e.GET("/ping", func(c echo.Context) error {
		return c.File("templates/icmp/ping.html")
	})

	e.POST("/pings", func(c echo.Context) error {
		// Meminta request dari host or IP Address dari Target
		target := c.FormValue("domain")

		// Ping Instance
		pinger, err := ping.NewPinger(target)
		if err != nil {
			panic(err)
		}

		pinger.Count = 3                  // jumlah packet yang akan dikirim
		pinger.Interval = time.Second     // interval antar packet
		pinger.Timeout = time.Second * 10 // total timeout operasi ping

		var packets []string

		pinger.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("Packet received from %s: icmp_seq=%d time=%v\n",
				pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packetInfo := fmt.Sprintf("Packet received from %s: icmp_seq=%d time=%v\n", pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packets = append(packets, packetInfo)
		}

		var buf bytes.Buffer
		pinger.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("Packet received from %s: icmp_seq=%d time=%v\n",
				pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packetInfo := fmt.Sprintf("Packet received from %s: icmp_seq=%d time=%v\n", pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packets = append(packets, packetInfo)
		}

		pinger.OnFinish = func(stats *ping.Statistics) {
			fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
			fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
			fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
				stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
		}

		fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
		err = pinger.Run() // mulai operasi ping
		if err != nil {
			panic(err)
		}

		type PingResult struct {
			Addr        string
			PacketsSent int
			PacketsRecv int
			PacketLoss  float64
			MinRtt      time.Duration
			AvgRtt      time.Duration
			MaxRtt      time.Duration
			StdDevRtt   time.Duration
			Result      string
			Packets     []string
		}

		data := PingResult{
			Addr:        pinger.Addr(),
			PacketsSent: 3,
			PacketsRecv: 3,
			PacketLoss:  0,
			MinRtt:      pinger.Statistics().MinRtt,
			AvgRtt:      pinger.Statistics().AvgRtt,
			MaxRtt:      pinger.Statistics().MaxRtt,
			StdDevRtt:   pinger.Statistics().StdDevRtt,
			Result:      buf.String(),
			Packets:     packets,
		}

		tmpl := template.Must(template.ParseFiles("templates/icmp/ping_result.html"))
		pings := data
		return c.HTML(http.StatusOK, renderTemplate(tmpl, pings))
	})

	e.Logger.Fatal(e.Start(":5000"))
}

func renderTemplate(tmpl *template.Template, data interface{}) string {
	var buf strings.Builder

	err := tmpl.Execute(&buf, data)
	if err != nil {
		log.Fatalf("Error rendering template: %s", err)
	}

	return buf.String()
}
