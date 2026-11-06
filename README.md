# agent-egress-guard

A small, standard-library Python check that looks at every outbound HTTP request from an AI agent's tools and refuses the ones carrying an email address, a key-shaped string, or a value you told it to watch for.

It exists because of a real bug report. In November 2026, a Claude Code user reported that the model had put their account email into the `User-Agent` header of web requests (GitHub issue anthropics/claude-code #107757). Anthropic shipped a default-on privacy module in v2.1.317 the same day. Earlier issues (#50702 in April, #81138 in July) had reported the same email sitting in the model's context. A model can write anything in its context into a request. A rule in a prompt asks it not to. A check in code runs every time.

This repo is that check, kept small enough to read in one sitting.

## What it does

`egress_guard.py` starts two local servers on 127.0.0.1:

- a **capture** server that logs what it receives, standing in for a website your agent visits
- a **guard** proxy that scans the request line (including the decoded URL) and every header before forwarding

If the guard finds a match, it answers `403` and the request never reaches the capture server.

It matches three things:

- anything shaped like an email address
- key-shaped strings (`sk-...`, `AKIA...`, `ghp_...`)
- exact values you add to `DENY`, such as the address you know is in your agent's context

## Run it

Python 3.9 or later and `curl`. No packages to install.

```bash
mkdir /tmp/egress-test          # must be a new, empty directory
python3 egress_guard.py /tmp/egress-test
rm -rf /tmp/egress-test
```

## What we saw

Run on 6 November 2026 on an Apple M4 Mac mini (Python 3.9.6, curl 8.7.1), placeholder data only:

```
default curl                     -> 200  ok
bot UA with contact URL          -> 200  ok
@handle in path                  -> 200  ok
email in User-Agent              -> 403  blocked: header:User-Agent=denylist, header:User-Agent=email
email in query, URL-encoded      -> 403  blocked: url=denylist, url=email
key-shaped header                -> 403  blocked: header:X-Api-Key=key
same email, base64 in header     -> 200  ok
requests that reached the capture server: 4
200 requests direct: 0.041s   through guard: 0.067s   per-request overhead: 0.13 ms
```

The last test case got through. The same placeholder address, base64-encoded in a header, does not match any pattern. A pattern list can always be dodged by an encoding it doesn't know about. Treat this as one layer, and keep personal data out of the agent's context where you can.

## Limits

- It reads plain HTTP. Most agent traffic is HTTPS, so in practice the check belongs inside the tool that builds the request (before TLS), or in a proxy you already terminate TLS at.
- Patterns miss things: encodings, split strings, data in request bodies.
- It does not decide what belongs in your agent's context. That decision comes first.

One gotcha from building it: if your `NO_PROXY` environment variable includes `127.0.0.1` or `localhost`, curl skips the proxy without telling you, and every test "passes". The script calls curl with `--noproxy ""` for that reason.

## Background

The longer write-up, covering where personal data enters an agent's context and the exits it can leave by, is on the KarmaBox site: [AI agent data leakage](https://www.karmaboxai.com/en/concept/factory/resources/ai-agent-data-leakage).

Maintained by the Karma Box team. KarmaBox makes a workspace that runs AI agents on local hardware, so we have a stake in this topic. The code stands on its own and works with any agent setup.

## License

MIT. See [LICENSE](LICENSE).
