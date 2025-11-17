package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
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
	"github.com/valyala/fastjson"
)

var (
	parserPool  fastjson.ParserPool
	headerCache sync.Map
)

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
		record := []string{
			p.Proxy,
			p.IP,
			fmt.Sprintf("%.2f", p.ElapsedMs),
			fmt.Sprintf("%.2f", float64(p.RoundtripLatency.Microseconds())/1000.0),
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

	p := parserPool.Get()
	defer parserPool.Put(p)

	for {
		select {
		case <-ctx.Done():
			return
		case proxy, ok := <-proxyQueue:
			if !ok {
				return
			}
			results <- testProxy(proxy, p)
		}
	}
}

func testProxy(proxyString string, p *fastjson.Parser) ProxyResult {
	res := ProxyResult{
		Proxy:   proxyString,
		Success: false,
		IP:      "",
	}

	parts, ok := parseProxy(proxyString)
	if !ok {
		return res
	}

	proxyURL := "http://" + parts.User + ":" + parts.Pass + "@" + parts.Host + ":" + parts.Port
	client, err := createTLSClient(proxyURL)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return res
	}

	res.TotalBandwidth = client.GetBandwidthTracker().GetTotalBandwidth()
	res.RoundtripLatency = time.Since(start)

	if !parseAPIResponse(body, p, &res) {
		return res
	}

	res.Success = true
	return res
}

func parseAPIResponse(body []byte, p *fastjson.Parser, res *ProxyResult) bool {
	v, err := p.ParseBytes(body)
	if err != nil {
		return false
	}

	res.IP = string(v.GetStringBytes("ip"))
	res.ElapsedMs = v.GetFloat64("elapsed_ms")

	location := v.Get("location")
	if location != nil {
		res.City = string(location.GetStringBytes("city"))
	}

	asn := v.Get("asn")
	if asn != nil {
		res.ASNOrg = string(asn.GetStringBytes("org"))
	}

	company := v.Get("company")
	if company == nil {
		return false
	}

	abuserScore := string(company.GetStringBytes("abuser_score"))
	fraudScore, ok := parseFraudScore(abuserScore)
	if !ok {
		return false
	}
	res.FraudScore = fraudScore

	return passesValidationFast(v, fraudScore)
}

func parseFraudScore(abuserScore string) (float64, bool) {
	if len(abuserScore) == 0 {
		return 0, false
	}

	end := strings.IndexByte(abuserScore, ' ')
	if end == -1 {
		end = len(abuserScore)
	}

	score, err := strconv.ParseFloat(abuserScore[:end], 64)
	if err != nil {
		return 0, false
	}

	return score, true
}

func passesValidationFast(v *fastjson.Value, fraudScore float64) bool {
	if v.GetBool("is_proxy") || v.GetBool("is_vpn") || v.GetBool("is_tor") ||
		v.GetBool("is_datacenter") || v.GetBool("is_abuser") {
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

	var headers http.Header
	if cached, ok := headerCache.Load(profileVersion); ok {
		headers = cached.(http.Header)
	} else {
		headers = http.Header{
			"accept":             {"*/*"},
			"accept-encoding":    {"gzip, deflate, br, zstd"},
			"accept-language":    {"en-US,en;q=0.9"},
			"connection":         {"keep-alive"},
			"origin":             {"https://ipapi.is"},
			"referer":            {"https://ipapi.is/"},
			"sec-fetch-dest":     {"empty"},
			"sec-fetch-mode":     {"cors"},
			"sec-fetch-site":     {"same-site"},
			"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + profileVersion + ".0.0.0 Safari/537.36"},
			"sec-ch-ua":          {`"Google Chrome";v="` + profileVersion + `", "Chromium";v="` + profileVersion + `", "Not-A.Brand";v="99"`},
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
		}
		headerCache.Store(profileVersion, headers)
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(requestTimeout),
		tlsclient.WithClientProfile(randomProfile),
		tlsclient.WithProxyUrl(proxyURL),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithBandwidthTracker(),
		tlsclient.WithDefaultHeaders(headers),
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
