package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
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
	ASN              int
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

type CurlRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
}

const (
	defaultInputFile     = "proxies.txt"
	defaultOutputFile    = "results.csv"
	defaultTimeout       = 5
	defaultMaxFraudScore = 0.0005
)

var (
	inputFile      string
	outputFile     string
	requestTimeout int
	maxFraudScore  float64
	requestFile    string
	targetURL      string
	asnFilter      int
	debugLog       bool
	logMutex       sync.Mutex
)

func init() {
	flag.StringVar(&inputFile, "input", defaultInputFile, "Input file containing proxies")
	flag.StringVar(&outputFile, "output", defaultOutputFile, "Output CSV file for results")
	flag.IntVar(&requestTimeout, "timeout", defaultTimeout, "Request timeout in seconds")
	flag.Float64Var(&maxFraudScore, "max-fraud-score", defaultMaxFraudScore, "Maximum acceptable fraud score")
	flag.StringVar(&requestFile, "request", "request.txt", "File containing curl command to test proxies against")
	flag.StringVar(&targetURL, "target", "", "Target URL to test proxies against (overrides request file)")
	flag.IntVar(&asnFilter, "asn", 0, "Filter proxies by ASN number (0 = no filter)")
	flag.BoolVar(&debugLog, "debug", false, "Enable debug logging to debug.log")
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

	fmt.Printf("Testing %d proxies...\n", len(proxies))

	successful, stats := testProxies(proxies)

	displayStats(len(proxies), stats, time.Since(start))

	if len(successful) == 0 {
		fmt.Println("\nNo working proxies found.")
		return
	}

	var curlReq CurlRequest
	var hasTarget bool

	if targetURL != "" {
		curlReq = CurlRequest{
			URL:     targetURL,
			Method:  "GET",
			Headers: make(map[string]string),
		}
		hasTarget = true
	} else if fileInfo, err := os.Stat(requestFile); err == nil && fileInfo.Size() > 0 {
		var err error
		curlReq, err = parseCurlFile(requestFile)
		if err != nil {
			fmt.Printf("Error parsing curl request: %v\n", err)
			return
		}
		hasTarget = true
	}

	if hasTarget {
		fmt.Printf("\nTesting %d proxies against target...\n", len(successful))
		successful = testProxiesAgainstTarget(successful, curlReq)
		fmt.Printf("✓ %d passed target test\n", len(successful))
	}

	if len(successful) > 0 {
		if err := writeCSVFile(outputFile, successful); err != nil {
			fmt.Printf("Error writing CSV file: %v", err)
			return
		}
		fmt.Printf("✓ Saved %d proxies to %s\n", len(successful), outputFile)
	} else {
		fmt.Println("\nNo proxies passed all tests.")
	}
}

func testProxiesAgainstTarget(proxies []ProxyResult, curlReq CurlRequest) []ProxyResult {
	type targetResult struct {
		proxy   string
		success bool
	}

	proxyQueue := make(chan string, len(proxies))
	results := make(chan targetResult, len(proxies))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < len(proxies); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case proxy, ok := <-proxyQueue:
					if !ok {
						return
					}
					results <- targetResult{
						proxy:   proxy,
						success: testProxyTarget(proxy, curlReq),
					}
				}
			}
		}()
	}

	go func() {
		for _, p := range proxies {
			proxyQueue <- p.Proxy
		}
		close(proxyQueue)
	}()

	bar := createProgressBar(len(proxies))

	passedMap := make(map[string]bool)
	var (
		mu          sync.Mutex
		collectorWg sync.WaitGroup
	)
	collectorWg.Add(1)

	go func() {
		defer collectorWg.Done()
		for res := range results {
			bar.Add(1)
			if res.success {
				mu.Lock()
				passedMap[res.proxy] = true
				mu.Unlock()
			}
		}
	}()

	wg.Wait()
	close(results)
	collectorWg.Wait()
	bar.Finish()

	var passed []ProxyResult
	for _, p := range proxies {
		if passedMap[p.Proxy] {
			passed = append(passed, p)
		}
	}

	return passed
}

func testProxies(proxies []string) ([]ProxyResult, Stats) {
	proxyQueue := make(chan string, len(proxies))
	results := make(chan ProxyResult, len(proxies))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < len(proxies); i++ {
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
	fmt.Printf("\n✓ Completed in %s - %d/%d passed (%.1f%%) - %.1f MB bandwidth\n",
		elapsed.Round(time.Millisecond), stats.SuccessCount, totalTested,
		float64(stats.SuccessCount)/float64(totalTested)*100,
		float64(stats.TotalBandwidth)/(1000*1000))
}

func writeCSVFile(filename string, proxies []ProxyResult) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"proxy",
		"ip",
		"elapsed_ms",
		"roundtrip_latency",
		"city",
		"asn",
		"asn_org",
		"fraud_score"}); err != nil {
		return err
	}

	for _, p := range proxies {
		record := []string{
			p.Proxy,
			p.IP,
			fmt.Sprintf("%.2f", p.ElapsedMs),
			fmt.Sprintf("%.2f", float64(p.RoundtripLatency.Microseconds())/1000.0),
			p.City,
			fmt.Sprintf("%d", p.ASN),
			p.ASNOrg,
			fmt.Sprintf("%.1f", p.FraudScore*1000),
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
	client, headers, err := createTLSClient(proxyURL, "https://ipapi.is", "https://ipapi.is/", true)
	if err != nil {
		return res
	}

	req, err := http.NewRequest("GET", "https://api.ipapi.is/", nil)
	if err != nil {
		return res
	}

	applyHeaders(req, headers)
	logRequest(proxyString, req, "")

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

	logResponse(proxyString, resp, body)

	res.TotalBandwidth = client.GetBandwidthTracker().GetTotalBandwidth()
	res.RoundtripLatency = time.Since(start)

	if !parseAPIResponse(body, p, &res) {
		return res
	}

	res.Success = true
	return res
}

func testProxyTarget(proxyString string, curlReq CurlRequest) bool {
	parts, ok := parseProxy(proxyString)
	if !ok {
		return false
	}

	parsedURL, err := url.Parse(curlReq.URL)
	if err != nil {
		return false
	}

	origin := parsedURL.Scheme + "://" + parsedURL.Host
	referer := curlReq.Headers["referer"]
	if referer == "" {
		referer = origin + "/"
	}

	proxyURL := "http://" + parts.User + ":" + parts.Pass + "@" + parts.Host + ":" + parts.Port
	client, baseHeaders, err := createTLSClient(proxyURL, origin, referer, false)
	if err != nil {
		return false
	}

	var bodyReader io.Reader
	if curlReq.Body != "" {
		bodyReader = strings.NewReader(curlReq.Body)
	}

	method := curlReq.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, curlReq.URL, bodyReader)
	if err != nil {
		return false
	}

	applyHeaders(req, baseHeaders)
	for key, value := range curlReq.Headers {
		lowerKey := strings.ToLower(key)
		if lowerKey != "user-agent" && !strings.HasPrefix(lowerKey, "sec-ch-ua") {
			req.Header.Set(key, value)
		}
	}

	logRequest(proxyString, req, curlReq.Body)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	logResponse(proxyString, resp, body)

	return resp.StatusCode >= 200 && resp.StatusCode < 400
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
		res.ASN = asn.GetInt("asn")
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

	return passesValidationFast(v, fraudScore, res.ASN)
}

func parseFraudScore(abuserScore string) (float64, bool) {
	if end := strings.IndexByte(abuserScore, ' '); end > 0 {
		abuserScore = abuserScore[:end]
	}
	if score, err := strconv.ParseFloat(abuserScore, 64); err == nil {
		return score, true
	}
	return 0, false
}

func passesValidationFast(v *fastjson.Value, fraudScore float64, asn int) bool {
	if !debugLog && (v.GetBool("is_proxy") || v.GetBool("is_vpn") || v.GetBool("is_tor") ||
		v.GetBool("is_datacenter") || v.GetBool("is_abuser")) {
		return false
	}
	return fraudScore <= maxFraudScore && (asnFilter == 0 || asn == asnFilter)
}

func applyHeaders(req *http.Request, headers http.Header) {
	for key, values := range headers {
		if key != http.HeaderOrderKey {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}
}

type logEntry struct {
	Proxy    string       `json:"proxy"`
	Time     string       `json:"time"`
	Request  logReq       `json:"request"`
	Response *logResp     `json:"response,omitempty"`
}

type logReq struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type logResp struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

var pendingRequests sync.Map

func logRequest(proxy string, req *http.Request, reqBody string) {
	if !debugLog {
		return
	}
	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, ", ")
	}
	entry := &logEntry{
		Proxy: proxy,
		Time:  time.Now().Format(time.RFC3339),
		Request: logReq{
			Method:  req.Method,
			URL:     req.URL.String(),
			Headers: headers,
			Body:    reqBody,
		},
	}
	pendingRequests.Store(proxy, entry)
}

func logResponse(proxy string, resp *http.Response, body []byte) {
	if !debugLog {
		return
	}
	val, ok := pendingRequests.LoadAndDelete(proxy)
	if !ok {
		return
	}
	entry := val.(*logEntry)

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	bodyStr := string(body)
	if len(body) > 1000 {
		bodyStr = string(body[:1000]) + "..."
	}

	entry.Response = &logResp{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    bodyStr,
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	f, err := os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	data, _ := json.Marshal(entry)
	f.Write(data)
	f.WriteString("\n")
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

func createTLSClient(proxyURL string, origin string, referer string, trackBandwidth bool) (tlsclient.HttpClient, http.Header, error) {
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

	cacheKey := profileVersion + "|" + origin
	var headers http.Header
	if cached, ok := headerCache.Load(cacheKey); ok {
		headers = cached.(http.Header)
	} else {
		headers = http.Header{
			"accept":             {"*/*"},
			"accept-encoding":    {"gzip, deflate, br, zstd"},
			"accept-language":    {"en-US,en;q=0.9"},
			"connection":         {"keep-alive"},
			"origin":             {origin},
			"referer":            {referer},
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
		headerCache.Store(cacheKey, headers)
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(requestTimeout),
		tlsclient.WithClientProfile(randomProfile),
		tlsclient.WithProxyUrl(proxyURL),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithDefaultHeaders(headers),
	}

	if trackBandwidth {
		options = append(options, tlsclient.WithBandwidthTracker())
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	return client, headers, err
}

func parseCurlFile(filename string) (CurlRequest, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return CurlRequest{}, err
	}

	curlCmd := string(data)
	curlCmd = strings.ReplaceAll(curlCmd, "\\\n", " ")
	curlCmd = strings.ReplaceAll(curlCmd, "^\n", " ")
	curlCmd = strings.ReplaceAll(curlCmd, "^\r\n", " ")
	curlCmd = strings.ReplaceAll(curlCmd, "\n", " ")
	curlCmd = strings.ReplaceAll(curlCmd, "\r\n", " ")
	curlCmd = strings.TrimSpace(curlCmd)

	req := CurlRequest{
		Method:  "GET",
		Headers: make(map[string]string),
	}

	parts := parseCurlCommand(curlCmd)

	for i := 0; i < len(parts); i++ {
		part := parts[i]

		if part == "curl" {
			continue
		}

		if part == "-X" || part == "--request" {
			if i+1 < len(parts) {
				req.Method = parts[i+1]
				i++
			}
			continue
		}

		if part == "-H" || part == "--header" {
			if i+1 < len(parts) {
				header := parts[i+1]
				colonIdx := strings.Index(header, ":")
				if colonIdx > 0 {
					key := strings.TrimSpace(strings.Trim(header[:colonIdx], "^"))
					value := strings.TrimSpace(strings.Trim(header[colonIdx+1:], "^"))
					req.Headers[strings.ToLower(key)] = value
				}
				i++
			}
			continue
		}

		if part == "--data" || part == "--data-raw" || part == "--data-binary" || part == "-d" {
			if i+1 < len(parts) {
				req.Body = parts[i+1]
				if req.Method == "GET" {
					req.Method = "POST"
				}
				i++
			}
			continue
		}

		if !strings.HasPrefix(part, "-") && req.URL == "" {
			req.URL = strings.Trim(part, "'\"^")
		}
	}

	if req.URL == "" {
		return CurlRequest{}, fmt.Errorf("no URL found in curl command")
	}

	return req, nil
}

func parseCurlCommand(cmd string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)
	isBashQuote := false

	for i := 0; i < len(cmd); i++ {
		c := rune(cmd[i])

		if c == '$' && i+1 < len(cmd) && cmd[i+1] == '\'' && !inQuote {
			isBashQuote = true
			inQuote = true
			quoteChar = '\''
			i++
			continue
		}

		if c == '\\' && inQuote && isBashQuote && i+1 < len(cmd) {
			i++
			next := rune(cmd[i])
			switch next {
			case 'n':
				current.WriteRune('\n')
			case 't':
				current.WriteRune('\t')
			case 'r':
				current.WriteRune('\r')
			case '\\':
				current.WriteRune('\\')
			case '\'':
				current.WriteRune('\'')
			default:
				current.WriteRune('\\')
				current.WriteRune(next)
			}
			continue
		}

		if c == '\'' || c == '"' {
			if !inQuote {
				inQuote = true
				quoteChar = c
				isBashQuote = false
			} else if c == quoteChar {
				inQuote = false
				quoteChar = 0
				isBashQuote = false
				if current.Len() > 0 {
					parts = append(parts, current.String())
					current.Reset()
				}
				continue
			} else {
				current.WriteRune(c)
			}
		} else if c == ' ' && !inQuote {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(c)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
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
