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
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/schollz/progressbar/v3"
	"github.com/valyala/fastjson"
)

type Config struct {
	InputFile      string
	OutputFile     string
	RequestFile    string
	TargetURL      string
	Timezone       string
	RequestTimeout int
	MaxFraudScore  float64
	ASNFilter      int
	DebugLog       bool
}

type Logger struct {
	enabled bool
	mu      sync.Mutex
	pending sync.Map
}

type WorkerPool[I, O any] struct {
	workers int
	fn      func(I) (O, bool)
}

type ProxyResult struct {
	Proxy      string
	IP         string
	City       string
	ASNOrg     string
	ASN        int
	Latency    time.Duration
	Bandwidth  int64
	FraudScore float64
	Elapsed    float64
}

type ProxyParts struct {
	Host, Port, User, Pass string
}

type CurlRequest struct {
	URL, Method string
	Headers     map[string]string
	Body        string
}

type LogEntry struct {
	Proxy string `json:"proxy"`
	Time  string `json:"time"`
	Req   LogReq `json:"request"`
	Resp  LogReq `json:"response,omitempty"`
}

type LogReq struct {
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Status int    `json:"status,omitempty"`
	Head   any    `json:"headers,omitempty"`
	Body   any    `json:"body,omitempty"`
}

var (
	config         Config
	logger         Logger
	parserPool     fastjson.ParserPool
	headerCache    sync.Map
	clientProfiles = []profiles.ClientProfile{
		profiles.Chrome_133_PSK, profiles.Chrome_131_PSK, profiles.Chrome_130_PSK,
		profiles.Chrome_124, profiles.Chrome_120, profiles.Chrome_117,
		profiles.Chrome_116_PSK, profiles.Chrome_112, profiles.Chrome_110,
	}
)

func init() {
	flag.StringVar(&config.InputFile, "input", "proxies.txt", "Input file containing proxies")
	flag.StringVar(&config.OutputFile, "output", "results.csv", "Output CSV file for results")
	flag.IntVar(&config.RequestTimeout, "timeout", 5, "Request timeout in seconds")
	flag.Float64Var(&config.MaxFraudScore, "max-fraud-score", 0.0005, "Maximum acceptable fraud score")
	flag.StringVar(&config.RequestFile, "request", "request.txt", "File containing curl command to test proxies against")
	flag.StringVar(&config.TargetURL, "target", "", "Target URL to test proxies against (overrides request file)")
	flag.IntVar(&config.ASNFilter, "asn", 0, "Filter proxies by ASN number (0 = no filter)")
	flag.StringVar(&config.Timezone, "timezone", "", "Filter proxies by timezone (e.g. 'America/New_York', 'EST', 'CET')")
	flag.BoolVar(&config.DebugLog, "debug", false, "Enable debug logging to debug.jsonl")
}

func main() {
	flag.Parse()
	logger.enabled = config.DebugLog
	start := time.Now()

	proxies, err := readProxies(config.InputFile)
	if err != nil {
		fmt.Printf("Error reading proxies: %v\n", err)
		return
	}
	if len(proxies) == 0 {
		fmt.Println("No proxies found.")
		return
	}

	fmt.Printf("Testing %d proxies...\n", len(proxies))

	concurrency := min(len(proxies), 5000)
	fmt.Printf("Using concurrency level: %d\n", concurrency)

	pool := NewWorkerPool(concurrency, func(p string) (ProxyResult, bool) {
		return testProxy(p)
	})
	results := pool.Run(proxies)

	printStats(len(proxies), results, time.Since(start))

	if len(results) == 0 {
		return
	}

	var curlReq CurlRequest
	hasTarget := false

	if config.TargetURL != "" {
		curlReq = CurlRequest{URL: config.TargetURL, Method: "GET", Headers: make(map[string]string)}
		hasTarget = true
	} else if fi, err := os.Stat(config.RequestFile); err == nil && fi.Size() > 0 {
		if req, err := parseCurlFile(config.RequestFile); err == nil {
			curlReq = req
			hasTarget = true
		} else {
			fmt.Printf("Error parsing request file: %v\n", err)
		}
	}

	if hasTarget {
		fmt.Printf("\nTesting %d proxies against target...\n", len(results))
		targetPool := NewWorkerPool(concurrency, func(r ProxyResult) (ProxyResult, bool) {
			if testProxyTarget(r.Proxy, curlReq) {
				return r, true
			}
			return r, false
		})
		results = targetPool.Run(results)
		fmt.Printf(" %d passed target test\n", len(results))
	}

	if len(results) > 0 {
		if err := writeCSV(config.OutputFile, results); err != nil {
			fmt.Printf("Error writing CSV: %v\n", err)
			return
		}
		fmt.Printf("Saved to %s\n", config.OutputFile)
	}
}

func NewWorkerPool[I, O any](workers int, fn func(I) (O, bool)) *WorkerPool[I, O] {
	return &WorkerPool[I, O]{
		workers: workers,
		fn:      fn,
	}
}

func (wp *WorkerPool[I, O]) Run(items []I) []O {
	total := len(items)
	if wp.workers > total {
		wp.workers = total
	}

	in := make(chan I, wp.workers*2)
	out := make(chan O, wp.workers*2)
	var wg sync.WaitGroup

	go func() {
		for _, item := range items {
			in <- item
		}
		close(in)
	}()

	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription("Testing"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(10),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetRenderBlankState(true),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < wp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case item, ok := <-in:
					if !ok {
						return
					}
					if res, ok := wp.fn(item); ok {
						out <- res
					}
					bar.Add(1)
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	var results []O
	for res := range out {
		results = append(results, res)
	}
	bar.Finish()
	return results
}

func testProxy(proxy string) (ProxyResult, bool) {
	parts, ok := parseProxy(proxy)
	if !ok {
		return ProxyResult{}, false
	}

	client, headers, err := createTLSClient(buildProxyURL(parts), "https://ipapi.is", "https://ipapi.is/", true)
	if err != nil {
		return ProxyResult{}, false
	}

	req, _ := http.NewRequest("GET", "https://api.ipapi.is/", nil)
	applyHeaders(req, headers)
	logger.LogRequest(proxy, req, "")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return ProxyResult{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ProxyResult{}, false
	}

	body, _ := io.ReadAll(resp.Body)
	logger.LogResponse(proxy, resp, body)

	res := ProxyResult{
		Proxy:     proxy,
		Latency:   time.Since(start),
		Bandwidth: client.GetBandwidthTracker().GetTotalBandwidth(),
	}

	p := parserPool.Get()
	defer parserPool.Put(p)

	if !parseAPIResponse(body, p, &res) {
		return ProxyResult{}, false
	}
	return res, true
}

func testProxyTarget(proxy string, curlReq CurlRequest) bool {
	parts, ok := parseProxy(proxy)
	if !ok {
		return false
	}

	parsed, err := url.Parse(curlReq.URL)
	if err != nil {
		return false
	}

	origin := parsed.Scheme + "://" + parsed.Host
	client, headers, err := createTLSClient(buildProxyURL(parts), origin, origin+"/", false)
	if err != nil {
		return false
	}

	var body io.Reader
	if curlReq.Body != "" {
		body = strings.NewReader(curlReq.Body)
	}

	req, err := http.NewRequest(curlReq.Method, curlReq.URL, body)
	if err != nil {
		return false
	}

	applyHeaders(req, headers)
	for k, v := range curlReq.Headers {
		lk := strings.ToLower(k)
		if lk != "user-agent" && !strings.HasPrefix(lk, "sec-ch-ua") {
			req.Header.Set(k, v)
		}
	}

	logger.LogRequest(proxy, req, curlReq.Body)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	logger.LogResponse(proxy, resp, bodyBytes)

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func parseAPIResponse(body []byte, p *fastjson.Parser, res *ProxyResult) bool {
	v, err := p.ParseBytes(body)
	if err != nil {
		return false
	}

	if !config.DebugLog && (v.GetBool("is_proxy") || v.GetBool("is_vpn") || v.GetBool("is_tor") ||
		v.GetBool("is_datacenter") || v.GetBool("is_abuser")) {
		return false
	}

	res.IP = string(v.GetStringBytes("ip"))
	res.Elapsed = v.GetFloat64("elapsed_ms")
	if loc := v.Get("location"); loc != nil {
		res.City = string(loc.GetStringBytes("city"))
	}
	if asn := v.Get("asn"); asn != nil {
		res.ASN = asn.GetInt("asn")
		res.ASNOrg = string(asn.GetStringBytes("org"))
	}

	if config.Timezone != "" {
		loc := v.Get("location")
		if loc == nil {
			return false
		}
		tz := string(loc.GetStringBytes("timezone"))
		if !matchTimezone(tz, config.Timezone) {
			return false
		}
	}

	if company := v.Get("company"); company != nil {
		scoreStr := string(company.GetStringBytes("abuser_score"))
		if idx := strings.IndexByte(scoreStr, ' '); idx > 0 {
			scoreStr = scoreStr[:idx]
		}
		if score, err := strconv.ParseFloat(scoreStr, 64); err == nil {
			res.FraudScore = score
		}
	}

	return res.FraudScore <= config.MaxFraudScore && (config.ASNFilter == 0 || res.ASN == config.ASNFilter)
}

func matchTimezone(tz, filter string) bool {
	if len(filter) == 0 {
		return true
	}

	tz = strings.ToLower(tz)
	filter = strings.ToLower(filter)

	if strings.Contains(tz, filter) {
		return true
	}

	switch filter {
	case "est", "edt":
		return strings.Contains(tz, "new_york") || strings.Contains(tz, "detroit") || strings.Contains(tz, "toronto")
	case "cst", "cdt":
		return strings.Contains(tz, "chicago") || strings.Contains(tz, "winnipeg")
	case "mst", "mdt":
		return strings.Contains(tz, "denver") || strings.Contains(tz, "edmonton")
	case "pst", "pdt":
		return strings.Contains(tz, "los_angeles") || strings.Contains(tz, "vancouver")
	case "cet", "cest":
		return strings.Contains(tz, "paris") || strings.Contains(tz, "berlin") || strings.Contains(tz, "rome") || strings.Contains(tz, "madrid")
	case "gmt", "bst":
		return strings.Contains(tz, "london") || strings.Contains(tz, "dublin")
	case "utc":
		return tz == "utc"
	}

	return false
}

func createTLSClient(proxyURL, origin, referer string, track bool) (tlsclient.HttpClient, http.Header, error) {
	profile := clientProfiles[rand.IntN(len(clientProfiles))]
	ver := profile.GetClientHelloId().Version

	key := ver + "|" + origin
	var headers http.Header
	if v, ok := headerCache.Load(key); ok {
		headers = v.(http.Header)
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
			"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + ".0.0.0 Safari/537.36"},
			"sec-ch-ua":          {`"Google Chrome";v="` + ver + `", "Chromium";v="` + ver + `", "Not-A.Brand";v="99"`},
			"sec-ch-ua-mobile":   {"?0"},
			"sec-ch-ua-platform": {`"Windows"`},
			http.HeaderOrderKey: {
				"accept", "accept-encoding", "accept-language", "connection", "origin", "referer",
				"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "user-agent", "sec-ch-ua",
				"sec-ch-ua-mobile", "sec-ch-ua-platform",
			},
		}
		headerCache.Store(key, headers)
	}

	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(config.RequestTimeout),
		tlsclient.WithClientProfile(profile),
		tlsclient.WithProxyUrl(proxyURL),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithDefaultHeaders(headers),
	}
	if track {
		opts = append(opts, tlsclient.WithBandwidthTracker())
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
	return client, headers, err
}

func parseProxy(s string) (ProxyParts, bool) {
	host, rest, ok1 := strings.Cut(s, ":")
	port, rest, ok2 := strings.Cut(rest, ":")
	user, pass, ok3 := strings.Cut(rest, ":")
	if !ok1 || !ok2 || !ok3 || strings.Contains(pass, ":") {
		return ProxyParts{}, false
	}
	return ProxyParts{host, port, user, pass}, true
}

func buildProxyURL(p ProxyParts) string {
	var sb strings.Builder
	sb.Grow(10 + len(p.User) + len(p.Pass) + len(p.Host) + len(p.Port))
	sb.WriteString("http://")
	sb.WriteString(p.User)
	sb.WriteByte(':')
	sb.WriteString(p.Pass)
	sb.WriteByte('@')
	sb.WriteString(p.Host)
	sb.WriteByte(':')
	sb.WriteString(p.Port)
	return sb.String()
}

func applyHeaders(req *http.Request, headers http.Header) {
	for k, v := range headers {
		if k != http.HeaderOrderKey {
			for _, val := range v {
				req.Header.Add(k, val)
			}
		}
	}
}

func readProxies(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if t := strings.TrimSpace(s.Text()); t != "" && !strings.HasPrefix(t, "#") {
			if _, ok := parseProxy(t); ok {
				lines = append(lines, t)
			}
		}
	}
	return lines, s.Err()
}

func writeCSV(filename string, proxies []ProxyResult) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"proxy", "ip", "elapsed_ms", "latency_ms", "city", "asn", "asn_org", "fraud_score"})
	for _, p := range proxies {
		w.Write([]string{
			p.Proxy, p.IP, fmt.Sprintf("%.2f", p.Elapsed),
			fmt.Sprintf("%.2f", float64(p.Latency.Microseconds())/1000.0),
			p.City, strconv.Itoa(p.ASN), p.ASNOrg, fmt.Sprintf("%.1f", p.FraudScore*1000),
		})
	}
	w.Flush()
	return w.Error()
}

func printStats(total int, results []ProxyResult, elapsed time.Duration) {
	var bw int64
	for _, r := range results {
		bw += r.Bandwidth
	}
	fmt.Printf("\nCompleted in %s - %d/%d passed (%.1f%%) - %.1f MB bandwidth\n",
		elapsed.Round(time.Millisecond), len(results), total,
		float64(len(results))/float64(total)*100, float64(bw)/1e6)
}

func parseCurlFile(f string) (CurlRequest, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return CurlRequest{}, err
	}
	cmd := strings.Join(strings.Fields(string(b)), " ")
	return parseCurlArgs(parseBashArgs(cmd)), nil
}

func parseCurlArgs(args []string) CurlRequest {
	req := CurlRequest{Method: "GET", Headers: make(map[string]string)}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-X", "--request":
			if i+1 < len(args) {
				req.Method = args[i+1]
				i++
			}
		case "-H", "--header":
			if i+1 < len(args) {
				if k, v, ok := strings.Cut(args[i+1], ":"); ok {
					req.Headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
				}
				i++
			}
		case "-d", "--data", "--data-raw", "--data-binary":
			if i+1 < len(args) {
				req.Body = args[i+1]
				if req.Method == "GET" {
					req.Method = "POST"
				}
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") && req.URL == "" && args[i] != "curl" {
				req.URL = strings.Trim(args[i], "'\"")
			}
		}
	}
	return req
}

func parseBashArgs(cmd string) []string {
	var args []string
	var buf strings.Builder
	var quote rune
	for _, r := range cmd {
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				buf.WriteRune(r)
			}
		} else if r == '\'' || r == '"' {
			quote = r
		} else if r == ' ' {
			if buf.Len() > 0 {
				args = append(args, buf.String())
				buf.Reset()
			}
		} else {
			buf.WriteRune(r)
		}
	}
	if buf.Len() > 0 {
		args = append(args, buf.String())
	}
	return args
}

func (l *Logger) LogRequest(proxy string, req *http.Request, body string) {
	if !l.enabled {
		return
	}
	h := make(map[string]string)
	for k, v := range req.Header {
		h[k] = strings.Join(v, ", ")
	}
	l.pending.Store(proxy, &LogEntry{
		Proxy: proxy, Time: time.Now().Format(time.RFC3339),
		Req: LogReq{Method: req.Method, URL: req.URL.String(), Head: h, Body: body},
	})
}

func (l *Logger) LogResponse(proxy string, resp *http.Response, body []byte) {
	if !l.enabled {
		return
	}
	v, ok := l.pending.LoadAndDelete(proxy)
	if !ok {
		return
	}
	e := v.(*LogEntry)
	h := make(map[string]string)
	for k, v := range resp.Header {
		h[k] = strings.Join(v, ", ")
	}

	e.Resp = LogReq{
		Status: resp.StatusCode,
		Head:   h,
		Body:   body,
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	f, _ := os.OpenFile("debug.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	json.NewEncoder(f).Encode(e)
}
