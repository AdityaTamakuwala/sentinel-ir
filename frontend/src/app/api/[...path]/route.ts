import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

async function proxyToBackend(
  req: NextRequest,
  context: { params: { path: string[] } }
): Promise<Response> {
  const upstreamBase = (process.env.INTERNAL_API_URL || "http://127.0.0.1:8000").replace(
    /\/+$/,
    ""
  );
  const pathSegments = context.params.path || [];
  const joinedPath = pathSegments.join("/");

  // Map `/api/health/...` cleanly to `/health/...` and `/api/v1/...` to `/api/v1/...`
  const targetPath =
    pathSegments[0] === "health" ? `/${joinedPath}` : `/api/${joinedPath}`;
  const targetUrl = `${upstreamBase}${targetPath}${req.nextUrl.search}`;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  });

  const clientIp =
    req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "127.0.0.1";
  headers.set("x-forwarded-for", clientIp);

  const hasBody = !["GET", "HEAD"].includes(req.method.toUpperCase());
  const init: RequestInit & { duplex?: "half" } = {
    method: req.method,
    headers,
    redirect: "manual",
    cache: "no-store",
  };

  if (hasBody && req.body) {
    init.body = req.body;
    init.duplex = "half";
  }

  try {
    const upstreamRes = await fetch(targetUrl, init);
    const resHeaders = new Headers();

    upstreamRes.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (!HOP_BY_HOP_HEADERS.has(lower) && lower !== "set-cookie") {
        resHeaders.set(key, value);
      }
    });

    // Preserve multiple Set-Cookie headers (access token, refresh token, CSRF token)
    const setCookies =
      typeof upstreamRes.headers.getSetCookie === "function"
        ? upstreamRes.headers.getSetCookie()
        : [];
    for (const cookie of setCookies) {
      resHeaders.append("Set-Cookie", cookie);
    }

    const contentType = upstreamRes.headers.get("content-type") || "";
    if (contentType.includes("text/event-stream")) {
      resHeaders.set("Cache-Control", "no-cache, no-transform");
      resHeaders.set("X-Accel-Buffering", "no");
    }

    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      statusText: upstreamRes.statusText,
      headers: resHeaders,
    });
  } catch {
    return Response.json(
      {
        error: {
          code: "UPSTREAM_UNAVAILABLE",
          message: "SENTINEL IR API backend is temporarily unreachable.",
          correlation_id: req.headers.get("x-request-id") || "proxy-error",
        },
      },
      { status: 502 }
    );
  }
}

export const GET = proxyToBackend;
export const POST = proxyToBackend;
export const PUT = proxyToBackend;
export const PATCH = proxyToBackend;
export const DELETE = proxyToBackend;
export const OPTIONS = proxyToBackend;

