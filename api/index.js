export const config = { runtime: "edge" };

const rawBase = process.env.TARGET_DOMAIN || "";

const TARGET_BASE = rawBase.endsWith("/")
  ? rawBase.slice(0, -1)
  : rawBase;


const ALLOWED_HOST = "ver.fazzatravel.com";

const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
]);

export default async function handler(req) {
  if (!TARGET_BASE) {
    return new Response("Misconfigured: TARGET_DOMAIN is not set", { status: 500 });
  }

  try {
    
    const baseUrl = new URL(TARGET_BASE);
    const host = baseUrl.hostname;

    if (
      host !== ALLOWED_HOST &&
      !host.endsWith("." + ALLOWED_HOST)
    ) {
      return new Response("Forbidden target host", { status: 403 });
    }

    const pathStart = req.url.indexOf("/", 8);
    const targetUrl =
      pathStart === -1
        ? TARGET_BASE + "/"
        : TARGET_BASE + req.url.slice(pathStart);

    const out = new Headers();
    let clientIp = null;

    for (const [k, v] of req.headers) {
      if (STRIP_HEADERS.has(k)) continue;
      if (k.startsWith("x-vercel-")) continue;

      if (k === "x-real-ip") {
        clientIp = v;
        continue;
      }

      if (k === "x-forwarded-for") {
        if (!clientIp) clientIp = v;
        continue;
      }

      if (k === "host") continue;

      out.set(k, v);
    }

    if (clientIp) {
      out.set("x-forwarded-for", clientIp);
    }

    const method = req.method;
    const hasBody = method !== "GET" && method !== "HEAD";

    return await fetch(targetUrl, {
      method,
      headers: out,
      body: hasBody ? req.body : undefined,
      duplex: "half",
      redirect: "manual",
    });

  } catch (err) {
    console.error("relay error:", err);
    return new Response("Bad Gateway: Tunnel Failed", { status: 502 });
  }
}
