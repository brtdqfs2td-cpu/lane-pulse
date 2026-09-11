"use strict";

// Bump this on any change to PRECACHE_URLS or when you want clients to
// pick up new page/asset versions on next load.
var CACHE_VERSION = "lane-pulse-v6";

var PRECACHE_URLS = [
  "./",
  "index.html",
  "coach.html",
  "summary.html",
  "offline-recording.js",
  "manifest.json",
  "coach.manifest.json",
  "icons/swimmer-192.png",
  "icons/swimmer-512.png",
  "icons/coach-192.png",
  "icons/coach-512.png",
  "fonts/manrope-variable.woff2",
  "fonts/ibm-plex-mono-400.woff2",
  "fonts/ibm-plex-mono-500.woff2",
  "fonts/ibm-plex-mono-600.woff2",
  "fonts/ibm-plex-mono-700.woff2"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then(function (cache) { return cache.addAll(PRECACHE_URLS); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(
          keys.filter(function (key) { return key !== CACHE_VERSION; })
              .map(function (key) { return caches.delete(key); })
        );
      })
      .then(function () { return self.clients.claim(); })
  );
});

// Two strategies, split by asset type:
//
// - Fonts and icons are content-versioned and effectively immutable, so
//   serve them cache-first for instant (and offline) loads.
// - HTML and JS are served network-first, with a cache-busting query param
//   appended to the *actual* fetch URL. Two earlier attempts at this still
//   served stale code: stale-while-revalidate served an old
//   offline-recording.js for a whole debugging session even in fresh
//   incognito windows, and a later "network-first + cache: no-store" fix
//   still returned identical stale results -- because GitHub Pages sits
//   behind a CDN (Fastly), and no-store only controls the *browser's own*
//   HTTP cache. A stale copy sitting at a CDN edge node is untouched by
//   that. The only fetch a CDN can never have cached is one for a URL it
//   has never seen before, so every fetch here carries a fresh timestamp
//   query param -- this is the one strategy that defeats every cache layer
//   (browser, service worker, and CDN) at once, with certainty.
function cacheBustedUrl(url) {
  var u = new URL(url);
  u.searchParams.set("swbust", Date.now() + "-" + Math.random().toString(36).slice(2));
  return u.toString();
}

self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;

  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  var isImmutableAsset = /\.(woff2|png)$/.test(url.pathname);

  if (isImmutableAsset) {
    event.respondWith(
      caches.open(CACHE_VERSION).then(function (cache) {
        return cache.match(req).then(function (cached) {
          if (cached) return cached;
          return fetch(req).then(function (response) {
            if (response && response.ok) cache.put(req, response.clone());
            return response;
          });
        });
      })
    );
    return;
  }

  event.respondWith(
    fetch(cacheBustedUrl(req.url), { cache: "no-store" }).then(function (response) {
      if (response && response.ok) {
        var copy = response.clone();
        // cache under the *original* request key so the offline fallback
        // below can still find it by the URL the page actually asked for
        caches.open(CACHE_VERSION).then(function (cache) { cache.put(req, copy); });
      }
      return response;
    }).catch(function () {
      return caches.open(CACHE_VERSION).then(function (cache) {
        return cache.match(req).then(function (cached) {
          return cached || Response.error();
        });
      });
    })
  );
});
