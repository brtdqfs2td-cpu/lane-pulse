# Lane Pulse

A small, self-contained heart-rate dashboard suite for a Bluetooth heart
rate sensor (built and tested with the **Polar Verity Sense**, but it works
with any sensor that broadcasts the standard BLE `heart_rate` service).

Everything runs client-side, straight from the sensor to the browser over
[Web Bluetooth](https://developer.mozilla.org/en-US/docs/Web/API/Web_Bluetooth_API) —
no build step, and no data leaves the browser unless a coach deliberately
connects a backend (see below, entirely optional). Session and practice
history are saved to `localStorage`, so local history is per-browser,
per-device. Fonts are self-hosted and a service worker precaches the app
shell, so every page keeps working with no signal (handy at a pool deck)
after the first visit.

## Pages

- **[`index.html`](index.html) — Lane Pulse.** Single-swimmer live view: BPM,
  HRV (rMSSD), training zones, a live chart, session history, and a demo-data
  mode for trying it out without hardware.
- **[`coach.html`](coach.html) — Lane Pulse Coach.** A coach's live
  multi-swimmer roster — pair several sensors at once and watch the whole
  set. Includes a Practice start/end control that logs a per-swimmer summary
  into a practice history list, and (optionally) a persistent team roster
  synced to a backend.
- **[`summary.html`](summary.html) — My Summary.** A read-only, per-athlete
  view of what the coach has synced — opened via a personal link, no login.
  Only works if the optional backend below is connected.

A small nav link in the header of `index.html`/`coach.html` switches between
the two. `summary.html` is reached only via a personal link from a coach,
since it's tied to one athlete's data.

## Requirements

- **Chrome or Edge**, desktop or Android. Web Bluetooth is not supported in
  Safari or any iOS browser (Apple hasn't implemented the API), so this
  suite won't work on an iPhone or iPad in any browser.
- **HTTPS** (or `localhost`) — Web Bluetooth requires a secure context.
- A sensor that's actually broadcasting, and not already connected
  elsewhere. A BLE heart rate sensor can only hold one active connection at
  a time — if it's already paired to a phone, watch, or another tab,
  disconnect it there first.

## Using it

1. Open the page (see **Requirements** above for browser/HTTPS constraints).
2. Click **Pair sensor** (or **+ Add swimmer** on the coach page) and pick
   the sensor from the browser's Bluetooth device picker.
3. On the swimmer page, optionally set your max HR (or age, to estimate it)
   to calibrate training zones, then **Start session** to begin logging.
4. On the coach page, pair each swimmer's sensor the same way, then
   **Start practice** to log the whole roster; **End practice** saves a
   summary for everyone into the history list below.
5. No sensor handy? Use **Try demo data** on the swimmer page to see the
   dashboard work with synthetic readings.

### Installing as an app

Each page has its own manifest and icon, so Chrome/Edge's install prompt
(address bar install icon, or the browser menu's "Install app…" /
"Add to Home screen") works independently for either page — install the
swimmer view, the coach view, or both.

### Offline use

Every page registers a shared service worker ([`service-worker.js`](service-worker.js))
that precaches the app shell — all three HTML pages, both manifests, the
icons, and the fonts. After the first successful load, reopening any page
(or an installed app) works with no network at all; the service worker also
refreshes its cache in the background whenever you do have a connection, so
you pick up new deploys automatically. If you change what the app shell
needs to load, bump `CACHE_VERSION` in `service-worker.js` so clients pick
up the new file list.

### Backend sync (optional)

`index.html` and `coach.html` work fully standalone with no setup at all —
everything above this section is true with zero configuration. If you want
a coach's synced practice data to reach individual athletes on their own
devices, there's an optional backend in [`worker/`](worker/): a small
Cloudflare Worker API in front of a MotherDuck (DuckDB) database. See
[`worker/src/index.ts`](worker/src/index.ts) for the endpoints and
[`worker/wrangler.toml`](worker/wrangler.toml) for setup — in short, a coach
enters an API URL + coach key once in `coach.html`'s "Backend sync" card,
builds a team roster there, and copies each athlete a personal
`summary.html` link. Nothing about the live BLE/GATT code changes based on
whether this is connected.

## Project layout

```
index.html              Swimmer view (Lane Pulse)
coach.html               Coach view (Lane Pulse Coach)
summary.html              Read-only per-athlete view (needs the backend)
manifest.json             PWA manifest for the swimmer view
coach.manifest.json        PWA manifest for the coach view
service-worker.js          Offline app-shell caching, shared by every page
icons/                     App icons referenced by the manifests
fonts/                     Self-hosted Manrope + IBM Plex Mono (woff2)
worker/                    Optional backend: Cloudflare Worker + MotherDuck
```

## Notes

- This is a training aid, not a medical device. Training zones are a
  heuristic based on percentage of max heart rate, not a clinical
  measurement.
- Everything is static HTML/CSS/JS — deploy it to any static host (GitHub
  Pages, Netlify, Vercel, etc.) as-is, no build step required.
- No third-party network calls at all (fonts are self-hosted), which also
  means nothing is sent to Google or any other outside service just from
  opening the page.
