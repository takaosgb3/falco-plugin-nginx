import type { Metadata } from "next";
import "./globals.css";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";

export const metadata: Metadata = {
  title: "FALCOYA - Craft more than detect",
  description: "Falco屋（FALCOYA）- 検知を超えた、セキュリティの職人技。エンタープライズ向けFalcoルール開発・チューニングサービス。",
  keywords: "Falco, security, monitoring, kubernetes, cloud native, セキュリティ, 監視",
  openGraph: {
    title: "FALCOYA - Craft more than detect",
    description: "検知を超えた、セキュリティの職人技",
    url: "https://falcoya.com",
    siteName: "FALCOYA",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
      },
    ],
    locale: "ja_JP",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "FALCOYA - Craft more than detect",
    description: "検知を超えた、セキュリティの職人技",
    images: ["/og-image.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ja">
      <body className="antialiased">
        <Navbar />
        <main className="min-h-screen">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
