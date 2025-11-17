# Proxy Quality Tester

Test residential proxies for quality and fraud detection using ipapi.is.

## Build

```bash
go build
```

## Usage

Create a `proxies.txt` file with one proxy per line in the format:
```
host:port:username:password
```

Run the tester:
```bash
./proxy-quality-tester
```

## Options

```
-input string
    Input file containing proxies (default "proxies.txt")
-output string
    Output CSV file for results (default "results.csv")
-timeout int
    Request timeout in seconds (default 5)
-max-fraud-score float
    Maximum acceptable fraud score (default 0.0005)
-asn int
    Filter proxies by ASN number (default 0 = no filter)
-request string
    File containing curl command to test proxies against (default "request.txt")
-target string
    Target URL to test proxies against (overrides request file)
-debug
    Enable debug logging to debug.log
```

## Examples

Basic usage:
```bash
./proxy-quality-tester -input myproxies.txt -output results.csv
```

Filter by ASN (e.g., AT&T):
```bash
./proxy-quality-tester -asn 7018
```

Test against a target URL:
```bash
./proxy-quality-tester -target https://api.example.com/endpoint
```

Test with curl command from file:
```bash
# Create request.txt with your curl command
./proxy-quality-tester
```

Debug mode (logs all requests/responses):
```bash
./proxy-quality-tester -debug
```

## Output

Results are saved to a CSV file with the following columns:
- proxy
- ip
- elapsed_ms
- roundtrip_latency
- city
- asn
- asn_org
- fraud_score
