"use strict";

// Bump this on any change to PRECACHE_URLS or when you want clients to
// pick up new page/asset versions on next load.
var CACHE_VERSION = "lane-pulse-v4";

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
// - HTML and JS are served network-first: always fetch the live version
//   when online (so code/page changes land on the very next load, with no
//   cache-busting dance), falling back to the cached copy only when the
//   network is unavailable. Stale-while-revalidate was serving an old
//   offline-recording.js for a whole debugging session even in fresh
//   incognito windows -- not worth the marginal speed on pages this small.
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
    fetch(req).then(function (response) {
      if (response && response.ok) {
        var copy = response.clone();
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
