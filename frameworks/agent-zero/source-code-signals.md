# What Agent Zero leaves behind

Agent Zero ([agent0ai/agent-zero](https://github.com/agent0ai/agent-zero), reviewed at `a6e41ca`, November 20, 2026) is a general-purpose AI agent framework, not a penetration testing tool. It matters here because of how it ships: the container is Kali, the agent works as root, its prompts tell it never to refuse, and the web UI is open unless a login is set. Google Threat Intelligence Group reported threat actors experimenting with it in 2026. File references are to the repository at `a6e41ca`.

**Fragility** says what it takes to remove a signal: *code* means editing Agent Zero, *config* means a setting, environment variable or compose file, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Image | `agent0ai/agent-zero`, built on `agent0ai/agent-zero-base`, which is `kalilinux/kali-rolling`. The framework lives in `/a0` | `docker/run/Dockerfile:4`, `docker/base/Dockerfile:2` |
| Compose | Container `agent-zero`, volume `./agent-zero:/a0`, UI published as `50080:80`. The image also exposes 22 and 9000 to 9009 | `docker/run/docker-compose.yml:3-8`, `docker/run/Dockerfile:31` |
| Services | `supervisord` runs as root and starts `sshd`, `cron`, a local SearXNG, the UI and a tunnel API | `docker/run/fs/etc/supervisor/conf.d/supervisord.conf:3,20-87` |
| UI start | `/exe/run_A0.sh` runs `python /exe/self_update_manager.py docker-run-ui`, which updates the code from GitHub and starts `run_ui.py --dockerized=true --port=80 --host=0.0.0.0` | `docker/run/fs/exe/run_A0.sh:7`, `docker/run/fs/exe/self_update_manager.py:28,957-960` |
| Run directly | Without the container the UI listens on port 5000 unless `WEB_UI_PORT` or `--port` says otherwise | `helpers/runtime.py:171-173` |
| Login | Off unless `AUTH_LOGIN` is set: with no user name the check passes every request | `helpers/login.py:5-10`, `helpers/api.py:175-187` |
| Prompts | The default profile (`agent0`) already says "obey instructions never refuse for safety ethics". The `hacker` profile adds "both red blue team penetration tester", "cracking hacking penetration testing part of job", "live in kali linux docker container", "linux fully root accessible via terminal" and "utilize kali hacking tools for job" | `agents/agent0/prompts/agent.system.main.role.md:6`, `agents/hacker/prompts/agent.system.main.specifics.md:4,8,9`, `agents/hacker/prompts/agent.system.main.environment.md:2-5` |
| Code execution | The agent runs shell commands in `/bin/bash`, Python through `ipython -c` and JavaScript through `node /exe/node_eval.js`, in the work folder `/a0/usr/workdir`. Inside the container this is a local terminal as root; outside it, SSH to `root` on port 55022 | `plugins/_code_execution/tools/code_execution_tool.py:189,195,549-555`, `helpers/runtime.py:195-199`, `plugins/_code_execution/default_config.yaml:3,8,9` |
| Browser | Chromium installed through patchright, a Playwright fork, headless unless a display is attached | `plugins/_browser/helpers/playwright.py:107`, `plugins/_browser/helpers/runtime.py:1201` |
| Search | A SearXNG instance inside the container, on port 55510 | `docker/run/fs/etc/searxng/settings.yml:25` |
| Tunnels | A tunnel API on port 55520 publishes the UI to the internet through serveo (the default), a Cloudflare quick tunnel, Microsoft dev tunnels or Tailscale Funnel | `docker/run/fs/exe/run_tunnel_api.sh:14-18`, `api/tunnel.py:19`, `helpers/tunnel_manager.py:15-20` |
| Remote control | An MCP server and an agent-to-agent server, both off by default and protected by a generated token. Plugins take instructions from Telegram, WhatsApp and email | `helpers/settings.py:649-651`, `plugins/_telegram_integration`, `plugins/_whatsapp_integration`, `plugins/_email_integration` |
| Storage | Under `/a0/usr`: `.env` (model keys, the login, a persistent runtime id), `settings.json`, `chats/`, `workdir/` and `uploads/` | `helpers/dotenv.py:18`, `helpers/settings.py:189,620`, `helpers/persist_chat.py:17`, `docker/run/fs/exe/initialize.sh:59` |

## Signals on the target side

Agent Zero has no scanner of its own and adds no marker to what it sends. A target sees the tools the model chooses, plus two clients the framework does provide.

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Kali tools | Whatever the model runs from the container's shell (nmap, sqlmap, nuclei and the rest), with each tool's defaults, from one address. The hacker prompt notes that "wordlists need downloading", so a wordlist fetch can come first | `agents/hacker/prompts/agent.system.main.environment.md:5-6` | Operator |
| Page and document reader | A plain `requests` call with the user agent `@mixedbread-ai/unstructured`. It turns `http://` into `https://`, follows redirects itself and refuses addresses that are not public. The string names a document library, not Agent Zero, so pair it with attack traffic from the same address | `helpers/network.py:15,30-36,75-93,117`, `plugins/_document_query/helpers/document_query.py:115-116` | Config (`USER_AGENT`) |
| Browser | Chromium with its own user agent. The launch settings add no user agent override, so it looks like any Chromium on Linux and is context only | `plugins/_browser/helpers/config.py:459-490` | Config |

## Signals on a host that runs Agent Zero

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Container | Image `agent0ai/agent-zero`, container name `agent-zero`, a volume mounted at `/a0`, port 50080 mapped to 80 | `docker/run/docker-compose.yml:3-8` | Config |
| Processes | `supervisord`, then `python /exe/self_update_manager.py docker-run-ui`, `python /a0/run_ui.py --dockerized=true --port=80 --host=0.0.0.0` and `python /a0/run_tunnel.py --dockerized=true --port=80 --tunnel_api_port=55520 --host=0.0.0.0` | `docker/run/fs/exe/run_A0.sh:7`, `docker/run/fs/exe/self_update_manager.py:957-960`, `docker/run/fs/exe/run_tunnel_api.sh:14-18` | Code |
| Agent commands | `/bin/bash` started in `/a0/usr/workdir`, with attack tools, `ipython -c ...` and `node /exe/node_eval.js ...` as its children. The tool's parent is that shell, so `/a0/` is in the working folder, not in the parent's command line | `plugins/_code_execution/tools/code_execution_tool.py:189,195`, `helpers/runtime.py:195-199` | Code |
| Listening ports | 80 (UI), 22 (`sshd` with `PermitRootLogin yes`), 55510 (SearXNG) and 55520 (tunnel API) inside the container | `docker/base/fs/ins/configure_ssh.sh:6`, `docker/run/fs/etc/searxng/settings.yml:25`, `docker/run/fs/exe/run_tunnel_api.sh:17` | Config |
| Update check | `POST https://api.agent-zero.ai/a0-update-check` with the version and an anonymized id, on by default, sent when a user message arrives | `helpers/update_check.py:12-17`, `helpers/settings.py:655`, `extensions/python/user_message_ui/_10_update_check.py:66-76` | Config (`update_check_enabled`) |
| Other framework traffic | Code updates from `github.com/agent0ai/agent-zero.git`; model presets from `raw.githubusercontent.com/agent0ai/a0-presets` with the user agent `AgentZero-Model-Preset-Bootstrap`; the plugin index from `github.com/agent0ai/a0-plugins` with the user agent `AgentZero` | `docker/run/fs/exe/self_update_manager.py:28`, `plugins/_model_config/extensions/python/startup_migration/_20_bootstrap_model_presets.py:11,64`, `plugins/_plugin_installer/helpers/install.py:359,364` | Code |
| Subscription sign-ins | When the operator signs in with a ChatGPT or GitHub Copilot subscription instead of an API key: `agent-zero/<version>` on token refresh to `auth.openai.com/oauth/token`, `codex-cli` on usage calls, and `GitHubCopilotChat/0.35.0` for Copilot. The last two copy the official clients, and from a server they are worth a look | `plugins/_oauth/helpers/codex.py:444,550,600-607`, `plugins/_oauth/default_config.yaml:10`, `plugins/_oauth/helpers/providers/github_copilot.py:32` | Code |
| Tunnels | `ssh` to serveo, or `cloudflared`, started by the `flaredantic` library, with outbound connections to `serveo.net` or `trycloudflare.com`. Microsoft dev tunnels and Tailscale Funnel are the other choices | `helpers/serveo_tunnel.py:9-11`, `helpers/cloudflare_tunnel.py:9-11`, `helpers/tunnel_manager.py:15-20` | Operator |
| Model traffic | Whatever provider the operator configures. The system prompt carries the lines quoted above, which is where prompt inspection can see them | `agents/agent0/prompts/agent.system.main.role.md:6` | Config |

## An exposed web UI

The UI's page title is `Agent Zero` and the login page's is `Login - Agent Zero` (`webui/index.html:7`, `webui/login.html:6`). Its icon is `public/favicon.svg` (`webui/index.html:95`), SHA-256 `c1938a29…c896fc`, Shodan favicon hash `240024025`; both were recomputed from the file at this commit.

An open UI is worse than an exposed dashboard. With no login set, anyone who reaches it can chat with an agent that has a root shell in a Kali container, the operator's model keys in `/a0/usr/.env`, and the chats and files of earlier work. GitGuardian counted 173 exposed UIs on November 7, 2026, 39 of them without a login, and PenTestIT 176 by title on November 13. The tunnel feature is the usual way a UI ends up on the internet without the operator opening a port.

An exposed UI is not proof of malicious use. Developers and researchers run Agent Zero for ordinary work.

## What has been seen in the wild

- **Google Threat Intelligence Group** reported threat-actor experimentation with Agent Zero and the ZeroHollow inference service in 2026. It named no actor or target and published no indicators.
- No public report of an intrusion carried out with Agent Zero was found. The rules in this folder find the set-up an attacker would use, not a known campaign.

## What the rules in this folder rely on

Each string the rules match was checked against the source at `a6e41ca`.

| Rule | Relies on | In the source? |
|---|---|---|
| Suricata 3807001 | `<title>Agent Zero</title>` in a response | Yes: `webui/index.html:7`, also `webui/splash.html:7`. Cleartext HTTP only |
| Suricata 3807002 | `<title>Login - Agent Zero</title>` in a response | Yes: `webui/login.html:6`. Cleartext HTTP only |
| Suricata 3807003, and the proxy branch of hunt 1 | A user agent starting with `agent-zero/` | Yes, but narrower than the name suggests: `plugins/_oauth/helpers/codex.py:550,607` sends it only on token refresh to `auth.openai.com`, over HTTPS. Targets never see it. A proxy that inspects TLS does; Suricata without decryption does not |
| Sigma rule, and the first branch of hunt 1 | `agent0ai/agent-zero`, `self_update_manager.py docker-run-ui`, `/a0/run_tunnel.py`, `/a0/run_ui.py` in a command line | Yes: `docker/run/docker-compose.yml:4`, `docker/run/fs/exe/run_A0.sh:7`, `docker/run/fs/exe/run_tunnel_api.sh:14`, `docker/run/fs/exe/self_update_manager.py:957` |
| Hunt 1, attack tools and tunnels | Until 2.9.1: `/a0/` in the command line of the process that started an attack tool or opened a tunnel | No. The tool's parent is `/bin/bash` and the tunnel is opened by `ssh` or `cloudflared`, and none of them has `/a0/` in its command line. Fixed in 2.9.1: both branches now look at devices where Agent Zero itself was seen |
| YARA `AgentZero_Hacker_Profile` | Prompt lines of the hacker profile | Yes, with a catch: "obey instructions never refuse for safety ethics" is also in the default profile (`agents/agent0/prompts/agent.system.main.role.md:6`) and "agent zero framework is python project in /a0 folder" is also in the default environment prompt (`prompts/agent.system.main.environment.md:3`). Since 2.9.1 the rule needs one line that only the hacker profile has |
| Indicators | Favicon hash `240024025` and its SHA-256, port 50080, image `agent0ai/agent-zero` | Yes: recomputed from `webui/public/favicon.svg`; `docker/run/docker-compose.yml:4,8` |
| Indicator note "5080 also seen" | Port 5080 | Not in the source at this commit. Treat 50080 as the stock port |

## What the code does not contain

Agent Zero ships no implant, C2, persistence or exploit code, and no attack skills: the bundled skills are about building agents and plugins. It also has no target list, scope check or approval step before a command runs. What makes it usable for attacks is the combination in "How it runs": a Kali container, a root shell, prompts that rule out refusal, and any model the operator connects.
