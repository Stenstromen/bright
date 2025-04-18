# BRIGHT - *BRaGIng RigHTs*

![Logo](./bright_logo.webp)

## Introduction

BRIGHT is a DNS, Email and Web standards testing tool. All related to a single tested domain.
It is written in Rust and interfacing is done via GraphQL API.

## Usage

Set the `CORS_ORIGIN` env variable to set Allowed Origin, default is `*`

Server listens on `http://0.0.0.0:8000`

Readiness and Liveness endpoints available at `/ready` and `/status`

Run with

```bash
cargo run
```

## Docker Image

```bash
docker run --rm -d \
-p 8000:8000 \
ghcr.io/stenstromen/bright:latest
```

## Example Request

Using cURL and jq:

```bash
curl --silent \
  --request POST \
  --url http://localhost:8000/graphql \
  --header 'Content-Type: application/json' \
  --data "$(jq -c -n --arg query '
{
  domainCheck(domain: "example.com") {
    dnssec {
      dnssecEnabled
    }
  }
}' '{"query":$query}')"|jq
```

## External Crates

- async-graphql
- hickory-resolver
- trust-dns-resolver
- tokio
- warp
- anyhow

## API Docs

Endpoint /graphql

```query
{
  domainCheck(domain: "example.com") {
    records {             # Check DNS Records
      name                # Domain being checked
      ttl                 # TTL of record
      recordType          # Type of record
      data                # Record contents
    }
    caa {                 # Check CAA DNS Records
      recordExists        # Bool if record exists
      reportingEnabled    # Bool if reporting is enabled
      records {           # Object[] containing CAA records
        name              # Domain being checked
        caaType           # Type of CAA record
        data              # CAA record contents
      }
    }
    ns {                  # Check DNS Nameserver for domain
      name                # Domain being checked
      records {           # Object[] containing NS records
        nsdomain          # Nameserver being checked FQDN 
        operational       # If nameserver is responding
        ipv4Available     # Bool if nameserver has ipv4 addresses available
        ipv6Available     # Bool if nameserver has ipv6 addresses available
        ipv4Addresses     # Array[] containing nameserver ipv4 addresses
        ipv6Addresses     # Array[] containing nameserver ipv6 addresses
        referralNsSoa     # Bool if nameserver is referred to in SOA
      }
      nsaddresses {       # Check ip addresses for nameserver(s)
        ip                # Ip address of nameserver
        ptr               # PTR record of nameserver ip address
        referralNsSoa     # Bool if nameserver is referred to in SOA
        operational       # Bool if nameserver ip is responding
        authoritative     # Bool if nameserver ip provides authoritative responses for domain 
        recursive         # Bool if nameserver ip resolves other domains other than provided domain
        udp               # Bool if nameserver port 53/udp responds
        tcp               # Bool is nameserver port 53/tcp responds
      }
      soa {               # Check SOA for domain
        primaryNs         # Primary nameserver in SOA
        contact           # Contact detail in SOA
        serial            # SOA serial
        refresh           # Refresh in seconds
        retry             # Retry in seconds
        expire            # Expire in seconds
        cacheTtl          # Resolution TTL in seconds
        soaTtl            # SOA TTL in seconds
      }
    }
    dnssec {              # Check DNSSEC status for domain
      dnssecEnabled       # Bool if DNSSEC is enabled or not
    }
  }
}
```

## Development Status

### Checks and Tests

#### Domain Name System (DNS) (`v1.0.0`)

- [x] DNS Zone - Nameservers, Nameserver Addresses and SOA
- [x] DNS Records - A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, CAA, DNSKEY, DS and SSHFP.
  - Subdomains www for A and AAAA records
  - Subdomains `_sip._tls`, `_sipfederationtls._tcp`, `_xmpp-client._tcp`, `_xmpp-server._tcp` for SRV records
  - Subdomains `_dmarc`, `_domainkey`, `_mta-sts` and `_smtp._tls` for TXT records
- [x] DNSSEC - If DNSSEC is enabled or not
- [x] CAA - If CAA records are present and if reporting is enabled

#### Email

- [x] Mail Servers - MX, A, AAAA and PTR records.
  - [] If the mail server is reachable and if it supports STARTTLS.
  - [x] If the mail server domain is DNSSEC signed.
- [ ] SMTP Server TLS
  - What TLS version is supported.
  - What ciphers are supported and their order.
  - If the DHE ciphers are at least 2048 bits and if the ECDHE ciphers are at least 256 bits.
- [ ] SMTP Server Certificates
  - Present the certificate chain.
  - If the certificate chain is valid and if it is signed by a trusted CA.
  - If the certificate is valid and if it is signed by a trusted CA.
  - If the private key is at least 2048 bits (RSA).
  - If the private key is at least 256 bits (ECDSA).
  - If the certificate matches the hostname.
  - If the certificate is valid (not after).
  - If the certificate has been revoked.
- [ ] MTA-STS Strict Transport Security
  - If MTA-STS is enabled.
  - If MTA-STS is enforced.
  - If MTA-STS is valid.
  - The certificate chain of the mta-sts web server is valid and signed by a trusted CA.
- [ ] SMTP TLS Reporting
  - If SMTP TLS-RPT policy is valid.
- [ ] DANE
  - If DANE is enabled and if it is valid.
- [ ] SPF
  - If SPF records are present and if they are valid.
- [ ] DMARC
  - If DMARC records are present and if they are valid.
  - If DMARC is enforced.
  - If external reporting is enabled and if it is valid.

#### Web

- [ ] HTTP (80)
  - Follow redirects and ensure that the final URL is https. For origin and www subdomain.
- [ ] HTTPS (443)
  - Follow redirects and ensure that the final URL is https. For origin and www subdomain.
- [ ] TLS
  - Check origin and www subdomain for TLS versions and cipherlist.
  - Check if TLS 1.1 and 1.0 are disabled.
  - Present the certificate chain.
  - If the certificate chain is valid and if it is signed by a trusted CA.
  - If the certificate is valid and if it is signed by a trusted CA.
  - If the private key is at least 2048 bits (RSA).
  - If the private key is at least 256 bits (ECDSA).
  - If the certificate matches the hostname.
  - If the certificate is valid (not after).
  - If the certificate has been revoked
- [ ] Certificates
  - Present the certificate chain.
  - If the certificate chain is valid and if it is signed by a trusted CA.
  - If the certificate is valid and if it is signed by a trusted CA.
  - If the private key is at least 2048 bits (RSA).
  - If the private key is at least 256 bits (ECDSA).
  - If the certificate matches the hostname.
  - If the certificate is valid (not after).
  - If the certificate has been revoked.
- [ ] Cookies
  - If cookies are secure and if they are HTTPOnly.
- [ ] Mixed Content
  - If mixed content is present.
  - If scripts, css and images are loaded over HTTPS.
  - If outboud links are over HTTPS.
- [ ] HTTP Strict Transport Security
  - If HSTS is enabled and if it is valid.
  - If policy has a long max-age.
  - If policy includes subdomains.
  - If policy includes preload.
  - If the policy is submitted to the HSTS preload list.
- [ ] Content Security Policy
  - If CSP is enabled and if it is valid.
  - If CSP is enforced.
  - If CSP is valid.
- [ ] Subresource Integrity
  - If external scripts and css links have SRI hashes and if they are valid.
  - If the remote resources allow cross-origin requests.
- [ ] Frame Options
  - If X-Frame-Options is enabled and is set to DENY.
- [ ] XSS Protection
  - If X-XSS-Protection is disabled and is set to 0.
- [ ] Content Type Options
  - If X-Content-Type-Options is enabled and is set to nosniff.
