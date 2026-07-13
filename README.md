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

if you are on a server with no browser, forward the port from your laptop and
run login there:

```
ssh -L 1455:127.0.0.1:1455 you@server 'cd pintr && ./pintr login'
```

then open the url in your laptop browser. the callback comes back through the
tunnel. you can also just copy an `auth.json` from your laptop to the server.

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

`pintr.giuli.dev` runs pintr in http mode behind a bearer token. add it to
claude code as a remote server:

```
claude mcp add --transport http --scope user pintr https://pintr.giuli.dev \
  --header "Authorization: Bearer YOUR_TOKEN"
```

ask the host owner for the token. every request needs that header or it gets a
401.

to run the http server yourself:

```
MCP_AUTH_TOKEN=your-secret ./pintr -http 127.0.0.1:8090
```

put a normal reverse proxy (nginx, caddy) with https in front of it. the server
streams its replies, so turn response buffering off in the proxy.

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
