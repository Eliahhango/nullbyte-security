/**
 * Technology fingerprinting from observed response data only.
 * Every detection cites the evidence that produced it, so a wrong guess is
 * traceable rather than asserted.
 */

export interface TechHit {
  name: string
  category: "server" | "framework" | "language" | "cms" | "cdn" | "analytics" | "library" | "security" | "other"
  confidence: "low" | "medium" | "high"
  evidence: string
}

export interface FingerprintInput {
  headers: Record<string, string>
  body?: string
  cookies?: string
  url?: string
}

function header(headers: Record<string, string>, name: string): string | undefined {
  const k = Object.keys(headers).find((x) => x.toLowerCase() === name.toLowerCase())
  return k ? headers[k] : undefined
}

export function fingerprint(input: FingerprintInput): TechHit[] {
  const hits: TechHit[] = []
  const add = (h: TechHit) => {
    if (!hits.some((x) => x.name === h.name && x.category === h.category)) hits.push(h)
  }
  const { headers, body = "", cookies = "", url = "" } = input

  const server = header(headers, "server")
  if (server) {
    const s = server.toLowerCase()
    const map: Array<[RegExp, string]> = [
      [/nginx/, "nginx"],
      [/apache/, "Apache httpd"],
      [/microsoft-iis/, "Microsoft IIS"],
      [/cloudflare/, "Cloudflare"],
      [/gunicorn/, "gunicorn"],
      [/uvicorn/, "uvicorn"],
      [/werkzeug/, "Werkzeug (Flask dev server)"],
      [/express/, "Express"],
      [/openresty/, "OpenResty"],
      [/caddy/, "Caddy"],
      [/lighttpd/, "lighttpd"],
      [/tomcat/, "Apache Tomcat"],
      [/jetty/, "Jetty"],
    ]
    for (const [re, name] of map) if (re.test(s)) add({ name, category: "server", confidence: "high", evidence: `Server: ${server}` })
  }

  const powered = header(headers, "x-powered-by")
  if (powered) {
    const p = powered.toLowerCase()
    if (/php/.test(p)) add({ name: "PHP", category: "language", confidence: "high", evidence: `X-Powered-By: ${powered}` })
    if (/asp\.net/.test(p)) add({ name: "ASP.NET", category: "framework", confidence: "high", evidence: `X-Powered-By: ${powered}` })
    if (/express/.test(p)) add({ name: "Express", category: "framework", confidence: "high", evidence: `X-Powered-By: ${powered}` })
    if (/next\.js/.test(p)) add({ name: "Next.js", category: "framework", confidence: "high", evidence: `X-Powered-By: ${powered}` })
  }

  for (const [name, hdr] of [
    ["Next.js", "x-nextjs-cache"],
    ["Vercel", "x-vercel-id"],
    ["Netlify", "x-nf-request-id"],
    ["Shopify", "x-shopify-stage"],
    ["Cloudflare", "cf-ray"],
    ["AWS ALB", "x-amzn-trace-id"],
    ["AWS CloudFront", "x-amz-cf-id"],
    ["GitHub Pages", "x-github-request-id"],
    ["Fastly", "x-served-by"],
    ["Akamai", "x-akamai-transformed"],
  ] as Array<[string, string]>) {
    const v = header(headers, hdr)
    if (v) add({ name, category: "cdn", confidence: "high", evidence: `header ${hdr}: ${v}` })
  }

  const c = cookies.toLowerCase()
  const cookieMap: Array<[RegExp, string, TechHit["category"]]> = [
    [/phpsessid/, "PHP", "language"],
    [/jsessionid/, "Java (Servlet)", "language"],
    [/asp\.net_sessionid/, "ASP.NET", "framework"],
    [/csrftoken|sessionid=.*django/, "Django", "framework"],
    [/laravel_session|xsrf-token/, "Laravel", "framework"],
    [/wordpress_|wp-settings/, "WordPress", "cms"],
    [/drupal/, "Drupal", "cms"],
    [/joomla/, "Joomla", "cms"],
    [/rack\.session/, "Ruby on Rails", "framework"],
    [/connect\.sid/, "Express", "framework"],
    [/_gh_sess/, "GitHub", "other"],
  ]
  for (const [re, name, category] of cookieMap) {
    if (re.test(c)) add({ name, category, confidence: "medium", evidence: `cookie matched /${re.source}/` })
  }

  const b = body
  const bodyMap: Array<[RegExp, string, TechHit["category"], TechHit["confidence"]]> = [
    [/wp-content|wp-includes/, "WordPress", "cms", "high"],
    [/__NEXT_DATA__|_next\/static/, "Next.js", "framework", "high"],
    [/ng-version=|ng-app/, "Angular", "framework", "medium"],
    [/data-reactroot|__REACT_DEVTOOLS/, "React", "library", "medium"],
    [/csrfmiddlewaretoken/, "Django", "framework", "high"],
    [/name="csrf-token"/, "Ruby on Rails", "framework", "medium"],
    [/drupal-settings-json|sites\/default\/files/, "Drupal", "cms", "high"],
    [/joomla|com_content/, "Joomla", "cms", "medium"],
    [/X-Powered-By: PHP/, "PHP", "language", "medium"],
    [/<meta name="generator" content="([^"]+)"/, "", "other", "high"],
    [/shopify\.theme|cdn\.shopify\.com/, "Shopify", "cms", "high"],
    [/gtag\(|googletagmanager\.com/, "Google Analytics/Tag Manager", "analytics", "high"],
    [/GoogleAnalyticsObject/, "Google Analytics (legacy)", "analytics", "medium"],
  ]
  for (const [re, name, category, confidence] of bodyMap) {
    const m = re.exec(b)
    if (!m) continue
    if (name === "") {
      add({ name: m[1] ?? "unknown generator", category: "other", confidence, evidence: `meta generator: ${m[0]}` })
    } else {
      add({ name, category, confidence, evidence: `body matched /${re.source}/` })
    }
  }

  if (url) {
    if (/\.php(?:$|\?)/.test(url)) add({ name: "PHP", category: "language", confidence: "low", evidence: `URL path ends in .php` })
    if (/\.aspx(?:$|\?)/.test(url)) add({ name: "ASP.NET", category: "framework", confidence: "low", evidence: `URL path ends in .aspx` })
    if (/\.jsp(?:$|\?)/.test(url)) add({ name: "Java (JSP)", category: "language", confidence: "low", evidence: `URL path ends in .jsp` })
  }

  return hits
}
