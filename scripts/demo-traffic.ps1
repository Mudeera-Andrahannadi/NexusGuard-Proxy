param([Parameter(Mandatory)][string]$Proxy)
# Sends a few typical requests through the proxy from this machine (client 1).
# NO_PROXY often lists 127.0.0.1, which would make curl skip the proxy.
$env:NO_PROXY = ''; $env:no_proxy = ''
$px = "http://${Proxy}:8888"
curl.exe -s -o NUL -w "HTTP   example.com        -> %{http_code}`n" -x $px http://example.com/
curl.exe -s -o NUL -w "HTTPS  example.org (CONNECT) -> %{http_code}`n" -x $px https://example.org/
curl.exe -s -o NUL -w "BLOCKED 169.254.169.254   -> %{http_code} (expected 403)`n" -x $px http://169.254.169.254/
