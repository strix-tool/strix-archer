# Acknowledgements & Credits

Strix Archer is an **orchestrator**. It does not contain, bundle, redistribute, or
modify any of the tools below — it simply **invokes them as separate programs**
that you install on your own machine (when present), and calls **free, key-less
public web APIs**, then formats the results into one report. All copyrights and
trademarks belong to their respective owners, and each tool/service is used under
its own license and terms. Archer would be nothing without this incredible
open-source and open-data ecosystem — **thank you** to every author, maintainer,
and operator. 🙏

If you use Archer, please support and star the upstream projects and respect each
service's rate limits and acceptable-use policy.

> Note on licensing: because Archer merely calls these programs over their
> command-line interfaces (the normal way any user would run them) and queries
> documented public HTTP APIs, it does not create a derivative work of them and
> does not relicense them. Install each tool from its official source and review
> each service's terms; their own licenses apply to your use of them.

## Wrapped command-line tools (optional — used only if installed)

Archer detects these on your `PATH` and wraps them; when they are absent it falls
back to its own built-in, standard-library checks so it still runs.

| Tool | Author / project | Homepage / repository | License |
|---|---|---|---|
| **Sherlock** | Sherlock Project | https://github.com/sherlock-project/sherlock | MIT |
| **Maigret** | soxoj | https://github.com/soxoj/maigret | MIT |
| **holehe** | megadose (Palenath) | https://github.com/megadose/holehe | GPL-3.0 |
| **theHarvester** | Christian Martorella (@laramies) & contributors | https://github.com/laramies/theHarvester | GPL-2.0 |
| **SpiderFoot** | Steve Micallef | https://github.com/smicallef/spiderfoot | MIT |
| **whois** | Marco d'Itri (Debian `whois`) | https://github.com/rfc1036/whois | GPL-2.0 |
| **dig** | ISC / BIND utilities | https://www.isc.org/bind/ | MPL-2.0 |

## Free public APIs & data sources (key-less)

Archer queries these documented public endpoints. It sends only what is needed for
the lookup — and for passwords it sends **only the first 5 characters of a SHA-1
hash** (k-anonymity), never the password itself.

| Service | Operator | Endpoint / docs | Notes |
|---|---|---|---|
| **Have I Been Pwned — Pwned Passwords** | Troy Hunt | https://haveibeenpwned.com/Passwords | k-anonymity range API; the password never leaves your machine |
| **XposedOrNot** | XposedOrNot | https://xposedornot.com | free, key-less email-breach API |
| **crt.sh** | Sectigo (Rob Stradling) | https://crt.sh | Certificate Transparency subdomain discovery |
| **rdap.org** | RDAP bootstrap proxy | https://about.rdap.org | structured domain registration data (RDAP) |
| **Cloudflare DNS over HTTPS** | Cloudflare | https://developers.cloudflare.com/1.1.1.1/ | DoH resolver |
| **Google Public DNS (DoH)** | Google | https://developers.google.com/speed/public-dns/docs/doh | DoH resolver |
| **GitHub REST API** | GitHub, Inc. | https://docs.github.com/rest | public, unauthenticated profile/commit metadata |
| **Gravatar** | Automattic | https://gravatar.com | public avatar/profile presence by email hash |

Username-presence checks also issue simple public HTTP requests to well-known
sites (GitHub, GitLab, Reddit, Mastodon-style profiles, etc.) exactly as a browser
would; those sites and their trademarks belong to their respective owners.

## Terminal UI dependencies

| Library | Author / project | Repository | License |
|---|---|---|---|
| **Textual** | Textualize (Will McGugan) | https://github.com/Textualize/textual | MIT |
| **Rich** | Textualize (Will McGugan) | https://github.com/Textualize/rich | MIT |

## Intended practice targets

Archer is built for **authorized** OSINT practice — e.g. **TryHackMe** rooms and
fictional personas you are permitted to investigate. Thank you to the platforms and
CTF authors who build safe, legal environments to learn in.

---

*License identifiers above reflect each project's stated license at the time of
writing; always check the project's current `LICENSE` file and each service's
current terms. If you are an author/operator and want your attribution changed or
removed, please open an issue and we'll fix it immediately.*
