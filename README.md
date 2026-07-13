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

you can run it two ways:

- **stdio** — a single local user, a client starts the binary for you.
- **http** — a hosted multi-user app with a dashboard, accounts, and the
  standard mcp oauth flow. this is what runs at `pintr.giuli.dev`.

## build

you need go 1.26 or newer.

```
go build -o pintr .
```

## sign in (one time)

```
./pintr login
```

open the printed url, sign in, done. the tokens are saved for later. this is
only for stdio mode; the hosted app links accounts from its dashboard instead.

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

## use it through pintr.giuli.dev (http, multi-user)

1. open `https://pintr.giuli.dev`, create an account (email + password). you
   get a personal access key, shown once.
2. on the dashboard, click **link a chatgpt account**, open the openai link and
   sign in. the browser then fails to open a `localhost:1455` page, which is
   expected — copy that url from the address bar and paste it back. you can
   link more than one account; pick one as the default and the rest are used as
   failover.
3. add the server to your mcp client by url:

```
claude mcp add --transport http pintr https://pintr.giuli.dev/mcp
```

the first time it connects it gets a 401, discovers the oauth endpoints, and
opens your browser. you log in to pintr and click allow; the client gets its
own token, refreshed automatically. the same flow works in any mcp client with
remote support: claude code, claude desktop (add a custom connector with the
url), codex, and so on.

for scripts and curl, send your access key directly:
`Authorization: Bearer pintr_...`.

## the tool: generate_image

| field | required | what it is |
| --- | --- | --- |
| `prompt` | yes | the full image prompt |
| `output_path` | yes | where to save the png |
| `reference_images` | no | file paths sent with the prompt to lock a look or a character |

the driver model is fixed to `gpt-5.6-terra` server-side, so callers cannot pass
a bogus model. it returns the saved path, the model, the account used, and how
long it took.

## host it yourself

```
PINTR_SECRET=<random 32+ chars> \
PINTR_DB=/var/lib/pintr/pintr.db \
PINTR_PUBLIC_URL=https://your-host \
./pintr -http 127.0.0.1:8090
```

- `PINTR_SECRET` signs the oauth tokens and encrypts the stored chatgpt tokens
  at rest — keep it secret and stable.
- `PINTR_DB` is the sqlite file path.
- `PINTR_PUBLIC_URL` is the public https base clients reach.

put a reverse proxy (nginx, caddy) with https in front. the mcp endpoint streams
its replies, so turn response buffering off.

## flags

| flag | default | what it does |
| --- | --- | --- |
| `-http ADDR` | off | serve the http app + mcp on ADDR instead of stdio |
| `-auth-file PATH` | `~/.config/pintr/auth.json` | stdio mode: where the local token lives |

## notes

this uses the public codex oauth client and normal user login, the same way the
codex cli and other tools do. in hosted mode, chatgpt tokens are encrypted at
rest and passwords are hashed with argon2id.
