// 将品牌配置应用到浏览器文档（标题与 favicon）。
// 供门户、WebAuth、管理后台登录页在加载品牌后统一调用。
export function applyBrandToDocument(brand) {
  if (!brand) return

  // 网站标题
  document.title = brand.title ? brand.title : "RemLink"

  // 网站图标
  const href = normalizeImageSrc(brand.favicon || "")
  let link = document.querySelector("link[rel='icon']:not([media])")
  if (!link) {
    link = document.createElement("link")
    link.rel = "icon"
    document.head.appendChild(link)
  }
  if (href) {
    link.href = href
  } else {
    const base = (typeof process !== "undefined" && process.env && process.env.BASE_URL) || "/"
    link.href = base + "favicon.svg"
  }
}
export function normalizeImageSrc(src) {
  if (!src) return ""
  const s = String(src).trim()
  if (s.startsWith("<svg") || s.startsWith("<?xml")) {
    return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(s)
  }
  return s
}
