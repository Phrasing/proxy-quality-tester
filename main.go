package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/schollz/progressbar/v3"
)

type APIResponse struct {
	IP           string  `json:"ip"`
	IsProxy      bool    `json:"is_proxy"`
	IsVPN        bool    `json:"is_vpn"`
	IsTor        bool    `json:"is_tor"`
	IsDatacenter bool    `json:"is_datacenter"`
	IsAbuser     bool    `json:"is_abuser"`
	ElapsedMs    float64 `json:"elapsed_ms"`
	Company      struct {
		AbuserScore string `json:"abuser_score"`
	} `json:"company"`
	ASN struct {
		Org string `json:"org"`
	} `json:"asn"`
	Location struct {
		Country string `json:"country"`
		City    string `json:"city"`
	} `json:"location"`
}

type ProxyResult struct {
	Proxy            string
	Success          bool
	IP               string
	TotalBandwidth   int64
	RoundtripLatency time.Duration
	ElapsedMs        float64
	City             string
	ASNOrg           string
	FraudScore       float64
}

type ProxyParts struct {
	Host string
	Port string
	User string
	Pass string
}

type Stats struct {
	SuccessCount   int64
	FailureCount   int64
	TotalBandwidth int64
}

const (
	defaultInputFile     = "proxies.txt"
	defaultOutputFile    = "results.csv"
	defaultWorkers       = 512
	defaultTimeout       = 5
	defaultMaxFraudScore = 0.0005
)

var (
	inputFile      string
	outputFile     string
	numWorkers     int
	requestTimeout int
	maxFraudScore  float64
)

func init() {
	flag.StringVar(&inputFile, "input", defaultInputFile, "Input file containing proxies")
	flag.StringVar(&outputFile, "output", defaultOutputFile, "Output CSV file for results")
	flag.IntVar(&numWorkers, "workers", defaultWorkers, "Number of concurrent workers")
	flag.IntVar(&requestTimeout, "timeout", defaultTimeout, "Request timeout in seconds")
	flag.Float64Var(&maxFraudScore, "max-fraud-score", defaultMaxFraudScore, "Maximum acceptable fraud score")
	flag.Parse()
}

func main() {
	start := time.Now()

	proxies, err := readProxies(inputFile)
	if err != nil {
		fmt.Printf("Error reading proxy file: %v", err)
		return
	}

	if len(proxies) == 0 {
		fmt.Println("No valid proxies found in", inputFile)
		return
	}

	fmt.Printf("Loaded %d proxies from %s\n", len(proxies), inputFile)
	fmt.Printf("Starting %d concurrent workers...\n\n", numWorkers)

	successful, stats := testProxies(proxies)

	displayStats(len(proxies), stats, time.Since(start))

	if len(successful) > 0 {
		if err := writeCSVFile(outputFile, successful); err != nil {
			fmt.Printf("Error writing CSV file: %v", err)
			return
		}
		fmt.Printf("✓ Written %d working proxies to %s\n", len(successful), outputFile)
	} else {
		fmt.Println("No working proxies found.")
	}
}

func testProxies(proxies []string) ([]ProxyResult, Stats) {
	proxyQueue := make(chan string, len(proxies))
	results := make(chan ProxyResult, len(proxies))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, proxyQueue, results, &wg)
	}

	go func() {
		for _, p := range proxies {
			proxyQueue <- p
		}
		close(proxyQueue)
	}()

	bar := createProgressBar(len(proxies))

	var (
		successful  []ProxyResult
		stats       Stats
		mu          sync.Mutex
		collectorWg sync.WaitGroup
	)
	collectorWg.Add(1)

	go func() {
		defer collectorWg.Done()
		for res := range results {
			bar.Add(1)
			if res.Success {
				atomic.AddInt64(&stats.SuccessCount, 1)
				atomic.AddInt64(&stats.TotalBandwidth, res.TotalBandwidth)
				mu.Lock()
				successful = append(successful, res)
				mu.Unlock()
			} else {
				atomic.AddInt64(&stats.FailureCount, 1)
			}
		}
	}()

	wg.Wait()
	close(results)
	collectorWg.Wait()
	bar.Finish()

	return successful, stats
}

func createProgressBar(total int) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetDescription("Testing"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(10),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetRenderBlankState(true),
	)
}

func displayStats(totalTested int, stats Stats, elapsed time.Duration) {
	proxiesPerSec := float64(totalTested) / elapsed.Seconds()

	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Testing Complete!\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Total Tested:    %d\n", totalTested)
	fmt.Printf("Elapsed Time:    %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Throughput:      %.1f proxies/sec\n", proxiesPerSec)
	fmt.Printf("Total Bandwidth: %.1f MB\n", float64(stats.TotalBandwidth)/(1000*1000))
	fmt.Printf("Successful:      %d (%.1f%%)\n", stats.SuccessCount, percentage(stats.SuccessCount, totalTested))
	fmt.Printf("Failed:          %d (%.1f%%)\n", stats.FailureCount, percentage(stats.FailureCount, totalTested))
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
}

func percentage(part int64, total int) float64 {
	return float64(part) / float64(total) * 100
}

func writeCSVFile(filename string, proxies []ProxyResult) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"proxy", "ip", "elapsed_ms", "roundtrip_latency", "city", "asn_org", "fraud_score"}); err != nil {
		return err
	}

	for _, p := range proxies {
		roundtripMs := float64(p.RoundtripLatency.Microseconds()) / 1000.0
		record := []string{
			p.Proxy,
			p.IP,
			fmt.Sprintf("%.2f", p.ElapsedMs),
			fmt.Sprintf("%.2f", roundtripMs),
			p.City,
			p.ASNOrg,
			fmt.Sprintf("%.4f", p.FraudScore),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func worker(ctx context.Context, proxyQueue <-chan string, results chan<- ProxyResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case proxy, ok := <-proxyQueue:
			if !ok {
				return
			}
			results <- testProxy(proxy)
		}
	}
}

func testProxy(proxyString string) ProxyResult {
	res := ProxyResult{
		Proxy:   proxyString,
		Success: false,
		IP:      "",
	}

	parts, ok := parseProxy(proxyString)
	if !ok {
		return res
	}

	client, err := createTLSClient(
		fmt.Sprintf("http://%s:%s@%s:%s", parts.User, parts.Pass, parts.Host, parts.Port))
	if err != nil {
		return res
	}

	req, err := http.NewRequest("GET", "https://api.ipapi.is/", nil)
	if err != nil {
		return res
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return res
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return res
	}

	res.TotalBandwidth = client.GetBandwidthTracker().GetTotalBandwidth()
	res.IP = apiResp.IP
	res.RoundtripLatency = time.Since(start)
	res.ElapsedMs = apiResp.ElapsedMs
	res.City = apiResp.Location.City
	res.ASNOrg = apiResp.ASN.Org

	fraudScore, ok := parseFraudScore(apiResp.Company.AbuserScore)
	if !ok {
		return res
	}
	res.FraudScore = fraudScore

	if !passesValidation(apiResp, fraudScore) {
		return res
	}

	res.Success = true
	return res
}

func parseFraudScore(abuserScore string) (float64, bool) {
	fields := strings.Fields(abuserScore)
	if len(fields) == 0 {
		return 0, false
	}

	score, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}

	return score, true
}

func passesValidation(apiResp APIResponse, fraudScore float64) bool {
	if apiResp.IsProxy || apiResp.IsVPN || apiResp.IsTor || apiResp.IsDatacenter || apiResp.IsAbuser {
		return false
	}

	return fraudScore <= maxFraudScore
}

func parseProxy(proxyString string) (ProxyParts, bool) {
	parts := strings.Split(proxyString, ":")
	if len(parts) != 4 {
		return ProxyParts{}, false
	}
	return ProxyParts{
		Host: parts[0],
		Port: parts[1],
		User: parts[2],
		Pass: parts[3],
	}, true
}

func createTLSClient(proxyURL string) (tlsclient.HttpClient, error) {
	clientProfiles := []profiles.ClientProfile{
		profiles.Chrome_133_PSK,
		profiles.Chrome_131_PSK,
		profiles.Chrome_130_PSK,
		profiles.Chrome_124,
		profiles.Chrome_120,
		profiles.Chrome_117,
		profiles.Chrome_116_PSK,
		profiles.Chrome_112,
		profiles.Chrome_110,
	}

	randomProfile := clientProfiles[rand.IntN(len(clientProfiles))]
	profileVersion := randomProfile.GetClientHelloId().Version

	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(requestTimeout),
		tlsclient.WithClientProfile(randomProfile),
		tlsclient.WithProxyUrl(proxyURL),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithBandwidthTracker(),
		tlsclient.WithDefaultHeaders(http.Header{
			"accept":             {"*/*"},
			"accept-encoding":    {"gzip, deflate, br, zstd"},
			"accept-language":    {"en-US,en;q=0.9"},
			"connection":         {"keep-alive"},
			"origin":             {"https://ipapi.is"},
			"referer":            {"https://ipapi.is/"},
			"sec-fetch-dest":     {"empty"},
			"sec-fetch-mode":     {"cors"},
			"sec-fetch-site":     {"same-site"},
			"user-agent":         {fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", profileVersion)},
			"sec-ch-ua":          {fmt.Sprintf(`"Google Chrome";v="%s", "Chromium";v="%s", "Not-A.Brand";v="99"`, profileVersion, profileVersion)},
			"sec-ch-ua-mobile":   {"?0"},
			"sec-ch-ua-platform": {`"Windows"`},
			http.HeaderOrderKey: {
				"accept",
				"accept-encoding",
				"accept-language",
				"connection",
				"origin",
				"referer",
				"sec-fetch-dest",
				"sec-fetch-mode",
				"sec-fetch-site",
				"user-agent",
				"sec-ch-ua",
				"sec-ch-ua-mobile",
				"sec-ch-ua-platform",
			},
		}),
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
}

func readProxies(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var proxies []string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if _, ok := parseProxy(line); ok {
			proxies = append(proxies, line)
		}
	}

	return proxies, scanner.Err()
}

func fatalError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
