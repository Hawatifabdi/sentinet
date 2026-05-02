# NVD API Configuration Guide

## Overview
The NVD (National Vulnerability Database) API is used by SentiNet to cross-reference device firmware and services against known vulnerabilities. Without an API key, lookups are rate-limited to ~5 requests/minute. With an API key, you get much faster lookups and better coverage.

## Getting an NVD API Key

1. **Visit**: https://services.nvd.nist.gov/rest/json/cves/2.0
2. **Request Access**: Click "Request API Key"
3. **Sign in/Register** with an email account
4. **Accept Terms** and submit
5. **Check your email** for the API key (usually instant)

## Configuration

### Option 1: Environment Variable (Recommended)
Set the API key before running the application:

```bash
export NVD_API_KEY="your-api-key-here"
python app.py
```

### Option 2: Persistent in Current Shell Session
```bash
source /home/kali/Desktop/sentinet/venv/bin/activate
export NVD_API_KEY="your-api-key-here"
python app.py
```

### Option 3: Add to `.bashrc` or `.zshrc` (Permanent)
```bash
# Add to ~/.zshrc (for zsh)
export NVD_API_KEY="your-api-key-here"

# Then reload:
source ~/.zshrc
```

## Verification

Run this to verify the API key is working:

```bash
export NVD_API_KEY="your-api-key-here"
python -c "
from scanner.nvd_client import search_cves
results = search_cves('OpenSSH', max_results=3)
print(f'✓ NVD API working! Found {len(results)} results')
for r in results[:2]:
    print(f'  - {r[\"cve_id\"]}: {r[\"severity\"]} (CVSS: {r[\"cvss_score\"]})')
"
```

## Current Status

**NVD API Key**: ❌ Not configured
- You can still scan, but vulnerability lookups will be slower
- Consider setting the API key for better performance

## Features

### With API Key:
- ✅ Full NVD vulnerability database access
- ✅ ~6 requests per second
- ✅ Complete CVE coverage
- ✅ Accurate CVSS scores

### Without API Key (Rate-limited):
- ✓ Basic vulnerability lookups work
- ✓ ~1 request per 6 seconds
- ✓ May miss some CVEs
- ✓ Still usable for small networks

## Troubleshooting

**Issue**: "NVD API error for 'X': HTTP 401"
- **Solution**: API key is invalid or expired. Get a new one from https://services.nvd.nist.gov

**Issue**: Scans are very slow
- **Solution**: API key is not set. Follow Option 1 or 2 above.

**Issue**: "NVD lookup failed for 'X': Connection timeout"
- **Solution**: Check internet connection or try again (NVD may be temporarily unavailable)
