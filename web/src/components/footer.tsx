import Link from "next/link"
import { Github, Twitter } from "lucide-react"

const footerLinks = {
  products: [
    { name: "Starter", href: "/products/starter" },
    { name: "Pro", href: "/products/pro" },
    { name: "Enterprise", href: "/products/enterprise" },
    { name: "Marketplace", href: "/products/marketplace" },
  ],
  resources: [
    { name: "Quickstart", href: "/resources/quickstart" },
    { name: "Lint Tool", href: "/resources/lint" },
    { name: "Traces", href: "/resources/traces" },
    { name: "Blog", href: "/blog" },
  ],
  company: [
    { name: "About", href: "/about" },
    { name: "Guild", href: "/guild" },
    { name: "Contact", href: "/contact" },
    { name: "Discord", href: "https://discord.gg/falcoya" },
  ],
  legal: [
    { name: "Terms", href: "/legal/terms" },
    { name: "Privacy", href: "/legal/privacy" },
  ],
}

export function Footer() {
  return (
    <footer className="border-t border-border bg-white">
      <div className="container mx-auto px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid grid-cols-2 gap-8 md:grid-cols-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-900">Products</h3>
            <ul className="mt-4 space-y-2">
              {footerLinks.products.map((link) => (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-primary"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-900">Resources</h3>
            <ul className="mt-4 space-y-2">
              {footerLinks.resources.map((link) => (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-primary"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-900">Company</h3>
            <ul className="mt-4 space-y-2">
              {footerLinks.company.map((link) => (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-primary"
                    {...(link.href.startsWith("http") && {
                      target: "_blank",
                      rel: "noopener noreferrer",
                    })}
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-900">Legal</h3>
            <ul className="mt-4 space-y-2">
              {footerLinks.legal.map((link) => (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="text-sm text-muted-foreground hover:text-primary"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <div className="mt-8 border-t border-border pt-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Link href="/" className="flex items-center space-x-2">
                <div className="h-6 w-6 rounded bg-gradient-to-br from-primary to-secondary" />
                <span className="font-heading font-semibold">FALCOYA</span>
              </Link>
              <span className="text-sm text-muted-foreground">
                Craft more than detect.
              </span>
            </div>
            <div className="flex space-x-4">
              <Link
                href="https://github.com/falcoya"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary"
              >
                <Github className="h-5 w-5" />
              </Link>
              <Link
                href="https://twitter.com/falcoya"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary"
              >
                <Twitter className="h-5 w-5" />
              </Link>
            </div>
          </div>
          <div className="mt-4 text-center text-sm text-muted-foreground">
            © 2025 FALCOYA. All rights reserved.
          </div>
        </div>
      </div>
    </footer>
  )
}