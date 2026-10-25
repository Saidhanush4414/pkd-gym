const C="pkd-v1";
self.addEventListener("install",e=>e.waitUntil(caches.open(C).then(c=>c.addAll(["/icon.svg"]))));
self.addEventListener("fetch",e=>{if(e.request.url.includes("/api/")||e.request.method!=="GET")return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});
