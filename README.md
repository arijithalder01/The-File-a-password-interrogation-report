# The File — a password interrogation report

A password strength tool that skips the boring meter and tells you a story instead: how long each of seven attackers — from a stranger typing by hand to a nation-state — would take to crack what you just typed.

Styled like a dark, minimal case file: typewriter type, rubber-stamp verdicts (`COMPROMISED` / `HELD`), a suspect profile checklist, and an entropy readout. Everything runs client-side.

## Why it's honest, not just decorative

- **Checks the leaked-password list first.** If your password is one of the most common ones ever breached, the report says so immediately — crack-time math is irrelevant if the attacker already has it memorized.
- **Crack times are computed in log-space**, so passphrases with huge keyspaces don't overflow into `Infinity` — they render as `~10^42 years` instead of breaking.
- **The footer says plainly** that these are worst-case, illustrative estimates for an offline attack against a poorly-hashed password, not a literal countdown for every real service.

## Features

- Live entropy calculation (bits, keyspace, character-pool breakdown)
- Seven attacker profiles with order-of-magnitude crack-time estimates
- Common/leaked password detection
- Show/hide toggle, zero external requests, zero storage — refresh and it's gone

## Running it

Open `index.html` directly, or serve the folder:

```bash
npx serve .
```

## Tech

Vanilla HTML, CSS, and JavaScript. No frameworks, no analytics, no password ever leaves the page — you can verify that by reading `script.js`, there's no `fetch` or `XMLHttpRequest` in it at all.

## License

MIT — do whatever you want with it.
