# pintr

pintr is a small mcp server that makes images. you give it a prompt and a
file path, it renders a png and saves it there. it signs in with your own
chatgpt account (the same login the codex cli uses) so there is no extra api
key to manage.

it speaks the model context protocol, so any mcp client (like claude code) can
call its one tool: `generate_image`.

## how it works

1. on first run it opens the openai sign in page in your browser.
2. it catches the login on a local port and saves your tokens to
   `~/.config/pintr/auth.json`. the tokens refresh on their own after that.
3. when a client calls `generate_image`, pintr sends the prompt to the
   codex image backend, reads the streamed result, and writes the png to the
   path you asked for.

you can run it two ways: over stdio (a client starts it for you) or over http
(you host it once and point clients at a url). the http mode is what runs at
`pintr.giuli.dev`.

## build

you need go 1.26 or newer.

```
go build -o pintr .
```

## sign in (one time)

```
./pintr login
```

open the printed url, sign in, done. the tokens are saved for later.

on a server there is an easier way: open `https://your-host/setup` in your
browser, enter the access key, click the openai link and sign in. the browser
then fails to open a `localhost:1455` page, which is expected. copy that url
from the address bar, paste it back into the setup page, done. no ssh tunnel
needed.

## use it locally (stdio)

point your mcp client at the binary. for claude code, add this to `.mcp.json`:

```json
{
  "mcpServers": {
    "pintr": {
      "command": "/full/path/to/pintr",
      "args": []
    }
  }
}
```

the client starts pintr when it needs it. if you have not signed in yet,
it walks you through the login first.

## use it through pintr.giuli.dev (http)

`pintr.giuli.dev` runs pintr in http mode. it speaks the standard mcp oauth
flow, so you do not paste any token into your config. just add the url:

```
claude mcp add --transport http --scope user pintr https://pintr.giuli.dev
```

the first time the client connects it gets a 401, discovers the oauth
endpoints, and opens your browser. you type the access key once on the consent
page and the client gets its own token (with automatic refresh). the same flow
works in any mcp client that supports remote servers: claude code, claude
desktop (add a custom connector with the url), codex, and so on.

for plain scripts and curl you can still send the access key directly as
`Authorization: Bearer <access key>`.

to run the http server yourself:

```
MCP_AUTH_TOKEN=your-secret PINTR_PUBLIC_URL=https://your-host ./pintr -http 127.0.0.1:8090
```

`MCP_AUTH_TOKEN` is the access key: it guards the consent page and `/setup`,
and signs the tokens pintr issues. `PINTR_PUBLIC_URL` is the public https url
clients use to reach the server. put a normal reverse proxy (nginx, caddy) with
https in front of it. the server streams its replies, so turn response
buffering off in the proxy.

## the tool: generate_image

| field | required | what it is |
| --- | --- | --- |
| `prompt` | yes | the full image prompt |
| `output_path` | yes | where to save the png |
| `reference_images` | no | file paths sent with the prompt to lock a look or a character |
| `model` | no | image model to use, defaults to `gpt-5.6-terra` |

it returns the saved path, the model used, and how long it took.

## flags

| flag | default | what it does |
| --- | --- | --- |
| `-http ADDR` | off | serve over http on ADDR instead of stdio |
| `-auth-file PATH` | `~/.config/pintr/auth.json` | where tokens live |

## notes

this uses the public codex oauth client and normal user login, the same way the
codex cli and other tools do. your tokens stay on your machine.
