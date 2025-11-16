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
-workers int
    Number of concurrent workers (default 512)
-timeout int
    Request timeout in seconds (default 5)
-max-fraud-score float
    Maximum acceptable fraud score (default 0.0005)
```

## Example

```bash
./proxy-quality-tester -input myproxies.txt -output results.csv -workers 256
```

## Output

Results are saved to a CSV file with the following columns:
- proxy
- ip
- elapsed_ms
- roundtrip_latency
- city
- asn_org
- fraud_score
