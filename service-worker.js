"use strict";

// Bump this on any change to PRECACHE_URLS or when you want clients to
// pick up new page/asset versions on next load.
var CACHE_VERSION = "lane-pulse-v3";

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

// Stale-while-revalidate: serve from cache instantly when available (this is
// what makes offline loads work), refresh the cache from the network in the
// background so the next load picks up whatever changed.
self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;

  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.open(CACHE_VERSION).then(function (cache) {
      return cache.match(req).then(function (cached) {
        var update = fetch(req).then(function (response) {
          if (response && response.ok) cache.put(req, response.clone());
          return response;
        }).catch(function () { return null; });

        if (cached) {
          event.waitUntil(update); // refresh in the background, don't block the response
          return cached;
        }
        return update.then(function (response) { return response || cached; });
      });
    })
  );
});
