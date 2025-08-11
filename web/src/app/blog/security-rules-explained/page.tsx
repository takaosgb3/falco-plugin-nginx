import { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Understanding Falco Nginx Plugin Security Rules - Complete Guide | FALCOYA",
  description: "Comprehensive guide to all 10 security rules in Falco Nginx Plugin. Learn SQL injection detection, XSS protection, command injection prevention, and more with real examples and response strategies.",
  keywords: "Falco Nginx Plugin, security rules, SQL injection, XSS, path traversal, command injection, web security, real-time monitoring",
  openGraph: {
    title: "Understanding Falco Nginx Plugin Security Rules - Complete Guide",
    description: "Master web security with our comprehensive guide to Falco Nginx Plugin's 10 security rules. Real examples included.",
    url: "https://falcoya.com/blog/security-rules-explained",
    siteName: "FALCOYA",
    images: [
      {
        url: "/og-security-rules.png",
        width: 1200,
        height: 630,
      },
    ],
    locale: "ja_JP",
    type: "article",
  },
  twitter: {
    card: "summary_large_image",
    title: "Understanding Falco Nginx Plugin Security Rules - Complete Guide",
    description: "Master web security with our comprehensive guide to Falco Nginx Plugin's 10 security rules.",
    images: ["/og-security-rules.png"],
  },
};

export default function SecurityRulesExplainedPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <header className="pt-24 pb-12 px-4">
        <div className="max-w-4xl mx-auto">
          {/* Breadcrumb */}
          <nav className="flex items-center space-x-2 text-sm text-gray-400 mb-8">
            <Link href="/" className="hover:text-purple-400 transition-colors">
              Home
            </Link>
            <span>/</span>
            <Link href="/blog" className="hover:text-purple-400 transition-colors">
              Blog
            </Link>
            <span>/</span>
            <span className="text-gray-300">Security Rules Explained</span>
          </nav>

          {/* Article Header */}
          <div className="mb-8">
            <div className="flex flex-wrap gap-2 mb-4">
              <span className="px-3 py-1 bg-gradient-to-r from-red-500 to-pink-500 text-white text-sm font-medium rounded-full">
                Featured Article | 注目記事
              </span>
              <span className="px-3 py-1 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-sm font-medium rounded-full">
                Technical Deep Dive | 技術詳細解説
              </span>
            </div>
            
            <h1 className="text-3xl md:text-5xl font-bold text-white mb-4 leading-tight">
              Understanding Falco Nginx Plugin Security Rules: A Complete Guide
            </h1>
            <h2 className="text-xl md:text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 mb-6 leading-tight">
              Falco Nginx Plugin セキュリティルール完全解説ガイド
            </h2>
            
            <div className="flex flex-wrap items-center gap-4 text-gray-400 text-sm mb-6">
              <span>Published: August 11, 2025</span>
              <span>•</span>
              <span>Reading Time: 15 minutes | 読了時間: 15分</span>
              <span>•</span>
              <span>By: Falco Nginx Plugin Team</span>
            </div>
            
            <div className="flex flex-wrap gap-2">
              {['Security Rules', 'Real-time Monitoring', 'Web Security', 'NGINX', 'Falco'].map(tag => (
                <span key={tag} className="px-2 py-1 bg-slate-800 text-gray-300 text-xs rounded border border-slate-700">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </div>
      </header>

      {/* Language Selection */}
      <section className="pb-8 px-4">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gradient-to-r from-slate-800/50 to-purple-800/30 backdrop-blur-sm border border-purple-500/20 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">🌐 Language Selection | 言語選択</h3>
            <div className="flex flex-wrap gap-4">
              <a
                href="#english-version"
                className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-medium rounded-lg transition-all duration-200"
              >
                🇺🇸 English Version
              </a>
              <a
                href="#japanese-version"
                className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700 text-white font-medium rounded-lg transition-all duration-200"
              >
                🇯🇵 日本語版
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Article Content */}
      <article className="pb-16 px-4">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gradient-to-br from-slate-800/40 to-purple-800/20 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-8 md:p-12">
            
            {/* Table of Contents */}
            <div className="mb-12">
              <h3 className="text-2xl font-bold text-white mb-6">📋 Table of Contents | 目次</h3>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-lg font-semibold text-purple-400 mb-3">🇺🇸 English Sections</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li><a href="#introduction" className="hover:text-purple-400 transition-colors">• Introduction</a></li>
                    <li><a href="#four-pillars" className="hover:text-purple-400 transition-colors">• Four Pillars of Security</a></li>
                    <li><a href="#critical-rules" className="hover:text-purple-400 transition-colors">• Critical Security Rules</a></li>
                    <li><a href="#implementation" className="hover:text-purple-400 transition-colors">• Implementation Guide</a></li>
                    <li><a href="#case-studies" className="hover:text-purple-400 transition-colors">• Real-World Case Studies</a></li>
                    <li><a href="#troubleshooting" className="hover:text-purple-400 transition-colors">• Troubleshooting</a></li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-red-400 mb-3">🇯🇵 日本語セクション</h4>
                  <ul className="space-y-2 text-gray-300">
                    <li><a href="#はじめに" className="hover:text-red-400 transition-colors">• はじめに</a></li>
                    <li><a href="#セキュリティ検出の4つの柱" className="hover:text-red-400 transition-colors">• セキュリティ検出の4つの柱</a></li>
                    <li><a href="#重要セキュリティルール" className="hover:text-red-400 transition-colors">• 重要セキュリティルール解説</a></li>
                    <li><a href="#実装ガイド" className="hover:text-red-400 transition-colors">• 実装ガイド</a></li>
                    <li><a href="#成功事例" className="hover:text-red-400 transition-colors">• 実際の成功事例</a></li>
                    <li><a href="#トラブルシューティング" className="hover:text-red-400 transition-colors">• トラブルシューティング</a></li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Quick Access to Full Documentation */}
            <div className="mb-12 p-6 bg-gradient-to-r from-purple-800/30 to-blue-800/30 rounded-xl border border-purple-500/30">
              <h3 className="text-xl font-bold text-white mb-4">📚 Complete Documentation Access</h3>
              <p className="text-gray-300 mb-4">
                This blog post provides an overview and practical insights. For the complete technical reference with all implementation details, visit our comprehensive documentation.
              </p>
              <p className="text-gray-400 mb-6">
                このブログ記事は概要と実用的な洞察を提供します。全ての実装詳細を含む完全な技術リファレンスについては、包括的なドキュメントをご覧ください。
              </p>
              <div className="flex flex-wrap gap-4">
                <Link
                  href="/docs/NGINX_RULES_REFERENCE.md"
                  className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white font-medium rounded-lg transition-all duration-200 group"
                >
                  📖 Complete Rules Reference
                  <svg className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
                <Link
                  href="/docs/installation.md"
                  className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-medium rounded-lg transition-all duration-200 group"
                >
                  🚀 Installation Guide
                  <svg className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
              </div>
            </div>

            {/* Article Preview Section */}
            <section id="introduction" className="mb-12">
              <h2 className="text-3xl font-bold text-white mb-6">🛡️ Introduction: Why Real-Time Web Security Monitoring Matters</h2>
              <div className="prose prose-invert max-w-none">
                <p className="text-gray-300 mb-4 leading-relaxed">
                  In today's digital landscape, web applications face an unprecedented number of cyber threats. From sophisticated SQL injection attacks to automated bot scanning, malicious actors continuously probe for vulnerabilities. Traditional security measures like firewalls and intrusion detection systems, while essential, often fall short when it comes to application-layer attacks that leverage legitimate HTTP traffic.
                </p>
                <p className="text-gray-300 mb-6 leading-relaxed">
                  <strong className="text-purple-400">Enter the Falco Nginx Plugin</strong> - a game-changing solution that transforms your nginx access logs into a powerful real-time security monitoring system. By analyzing every HTTP request as it flows through your web server, this plugin provides immediate detection and alerting for various attack patterns.
                </p>
                
                <div className="bg-gradient-to-r from-blue-800/20 to-cyan-800/20 border border-blue-500/30 rounded-lg p-6 mb-6">
                  <h3 className="text-xl font-semibold text-blue-400 mb-3">⚡ Key Performance Metrics</h3>
                  <div className="grid md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Processing Time:</span> <span className="text-green-400 font-mono">&lt; 1ms per event</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Throughput:</span> <span className="text-green-400 font-mono">10,000+ events/second</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Memory Usage:</span> <span className="text-green-400 font-mono">&lt; 50MB</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Detection Rules:</span> <span className="text-green-400 font-mono">10 comprehensive rules</span>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* Four Pillars Section */}
            <section id="four-pillars" className="mb-12">
              <h2 className="text-3xl font-bold text-white mb-6">🏛️ The Four Pillars of Security Detection</h2>
              <p className="text-gray-300 mb-8 leading-relaxed">
                The Falco Nginx Plugin employs a comprehensive security detection framework organized using <strong className="text-purple-400">MECE (Mutually Exclusive, Collectively Exhaustive)</strong> principles:
              </p>
              
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-gradient-to-br from-red-800/30 to-pink-800/30 border border-red-500/30 rounded-lg p-6">
                  <div className="flex items-center mb-4">
                    <span className="text-2xl mr-3">🚨</span>
                    <h3 className="text-xl font-bold text-red-400">Security Attack Detection</h3>
                  </div>
                  <div className="text-sm text-gray-300 mb-3">
                    <span className="font-semibold">5 Rules</span> • <span className="text-red-400">CRITICAL/WARNING</span>
                  </div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• SQL Injection Attempts</li>
                    <li>• Cross-Site Scripting (XSS)</li>
                    <li>• Path/Directory Traversal</li>
                    <li>• Command Injection</li>
                    <li>• Sensitive File Access</li>
                  </ul>
                </div>

                <div className="bg-gradient-to-br from-blue-800/30 to-cyan-800/30 border border-blue-500/30 rounded-lg p-6">
                  <div className="flex items-center mb-4">
                    <span className="text-2xl mr-3">🔍</span>
                    <h3 className="text-xl font-bold text-blue-400">Reconnaissance Detection</h3>
                  </div>
                  <div className="text-sm text-gray-300 mb-3">
                    <span className="font-semibold">1 Rule</span> • <span className="text-blue-400">NOTICE</span>
                  </div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• Suspicious User Agents</li>
                    <li>• Attack Tool Detection</li>
                    <li>• Scanner Identification</li>
                  </ul>
                </div>

                <div className="bg-gradient-to-br from-yellow-800/30 to-orange-800/30 border border-yellow-500/30 rounded-lg p-6">
                  <div className="flex items-center mb-4">
                    <span className="text-2xl mr-3">🔐</span>
                    <h3 className="text-xl font-bold text-yellow-400">Authentication Attacks</h3>
                  </div>
                  <div className="text-sm text-gray-300 mb-3">
                    <span className="font-semibold">1 Rule</span> • <span className="text-yellow-400">NOTICE</span>
                  </div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• Brute Force Detection</li>
                    <li>• Failed Login Monitoring</li>
                    <li>• Authentication Abuse</li>
                  </ul>
                </div>

                <div className="bg-gradient-to-br from-green-800/30 to-teal-800/30 border border-green-500/30 rounded-lg p-6">
                  <div className="flex items-center mb-4">
                    <span className="text-2xl mr-3">📊</span>
                    <h3 className="text-xl font-bold text-green-400">System Monitoring</h3>
                  </div>
                  <div className="text-sm text-gray-300 mb-3">
                    <span className="font-semibold">3 Rules</span> • <span className="text-green-400">INFO/NOTICE</span>
                  </div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    <li>• HTTP 4xx Client Errors</li>
                    <li>• HTTP 5xx Server Errors</li>
                    <li>• Large Response Detection</li>
                  </ul>
                </div>
              </div>
            </section>

            {/* SQL Injection Deep Dive */}
            <section id="critical-rules" className="mb-12">
              <h2 className="text-3xl font-bold text-white mb-6">🔴 Deep Dive: SQL Injection Detection</h2>
              <div className="bg-gradient-to-r from-red-800/20 to-pink-800/20 border border-red-500/30 rounded-lg p-6 mb-6">
                <h3 className="text-xl font-semibold text-red-400 mb-4">Critical Security Rule: Database Protection</h3>
                <p className="text-gray-300 mb-4 leading-relaxed">
                  SQL injection remains one of the most dangerous web application vulnerabilities, capable of exposing entire databases, bypassing authentication, and enabling complete system compromise. Our detection engine monitors both URL paths and query strings for common attack patterns.
                </p>
                
                <h4 className="text-lg font-semibold text-white mb-3">Detection Patterns:</h4>
                <div className="bg-slate-900/50 rounded-lg p-4 mb-4">
                  <pre className="text-green-400 text-sm overflow-x-auto">
{`• ' OR     (Authentication bypass)
• ' AND    (Condition manipulation)  
• UNION SELECT (Data extraction)
• ; DROP   (Data destruction)
• /* */    (Comment injection)`}
                  </pre>
                </div>

                <h4 className="text-lg font-semibold text-white mb-3">Real-World Example:</h4>
                <div className="bg-slate-900/50 rounded-lg p-4 mb-4">
                  <div className="text-red-400 text-sm mb-2">Attack Request:</div>
                  <pre className="text-gray-300 text-sm mb-3 overflow-x-auto">
{`GET /login?username=admin' OR '1'='1&password=anything`}
                  </pre>
                  <div className="text-orange-400 text-sm mb-2">Generated Alert:</div>
                  <pre className="text-gray-300 text-sm overflow-x-auto">
{`SQL injection attempt detected 
(remote_addr=203.0.113.45 method=GET path=/login 
 query=username=admin' OR '1'='1&password=anything status=200)`}
                  </pre>
                </div>

                <h4 className="text-lg font-semibold text-white mb-3">Immediate Response Actions:</h4>
                <div className="grid md:grid-cols-3 gap-4 text-sm">
                  <div className="bg-red-900/30 rounded-lg p-3">
                    <div className="font-semibold text-red-400 mb-1">1. Block IP</div>
                    <div className="text-gray-300">Temporarily restrict access from attacking IP</div>
                  </div>
                  <div className="bg-orange-900/30 rounded-lg p-3">
                    <div className="font-semibold text-orange-400 mb-1">2. Log Analysis</div>
                    <div className="text-gray-300">Examine full request context and history</div>
                  </div>
                  <div className="bg-yellow-900/30 rounded-lg p-3">
                    <div className="font-semibold text-yellow-400 mb-1">3. Harden App</div>
                    <div className="text-gray-300">Strengthen input validation systems</div>
                  </div>
                </div>
              </div>
            </section>

            {/* Implementation Quick Start */}
            <section id="implementation" className="mb-12">
              <h2 className="text-3xl font-bold text-white mb-6">🚀 Quick Implementation Guide</h2>
              <div className="bg-gradient-to-r from-green-800/20 to-teal-800/20 border border-green-500/30 rounded-lg p-6">
                <h3 className="text-xl font-semibold text-green-400 mb-4">Get Started in 3 Steps:</h3>
                
                <div className="space-y-4">
                  <div className="flex items-start space-x-4">
                    <div className="bg-green-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold flex-shrink-0">1</div>
                    <div>
                      <div className="font-semibold text-white mb-2">Download & Install</div>
                      <div className="bg-slate-900/50 rounded p-3 text-sm overflow-x-auto">
                        <pre className="text-green-400">
{`wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/libfalco-nginx-plugin-linux-amd64.so
sudo cp libfalco-nginx-plugin-linux-amd64.so /usr/share/falco/plugins/`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-start space-x-4">
                    <div className="bg-green-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold flex-shrink-0">2</div>
                    <div>
                      <div className="font-semibold text-white mb-2">Deploy Rules</div>
                      <div className="bg-slate-900/50 rounded p-3 text-sm overflow-x-auto">
                        <pre className="text-green-400">
{`wget https://github.com/takaosgb3/falco-plugin-nginx/releases/latest/download/nginx_rules.yaml
sudo cp nginx_rules.yaml /etc/falco/rules.d/`}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-start space-x-4">
                    <div className="bg-green-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold flex-shrink-0">3</div>
                    <div>
                      <div className="font-semibold text-white mb-2">Activate Monitoring</div>
                      <div className="bg-slate-900/50 rounded p-3 text-sm overflow-x-auto">
                        <pre className="text-green-400">
{`sudo systemctl restart falco
sudo journalctl -u falco -f  # View real-time alerts`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* Japanese Introduction */}
            <section id="japanese-version" className="mb-12 border-t border-slate-700 pt-12">
              <h2 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-pink-400 mb-6">🇯🇵 日本語版: はじめに</h2>
              <div className="prose prose-invert max-w-none">
                <p className="text-gray-300 mb-4 leading-relaxed">
                  現代のデジタル環境において、Webアプリケーションはこれまでにない数のサイバー脅威に直面しています。巧妙なSQLインジェクション攻撃から自動化されたボットスキャンまで、悪意のある攻撃者は継続的に脆弱性を探し続けています。
                </p>
                <p className="text-gray-300 mb-6 leading-relaxed">
                  <strong className="text-red-400">Falco Nginx Plugin の登場</strong> - これは、nginxのアクセスログを強力なリアルタイムセキュリティ監視システムに変える画期的なソリューションです。Webサーバーを通過するすべてのHTTPリクエストを分析することで、このプラグインは様々な攻撃パターンの即座の検出とアラートを提供します。
                </p>
                
                <div className="bg-gradient-to-r from-red-800/20 to-pink-800/20 border border-red-500/30 rounded-lg p-6 mb-6">
                  <h3 className="text-xl font-semibold text-red-400 mb-3">⚡ 主要パフォーマンス指標</h3>
                  <div className="grid md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">処理時間:</span> <span className="text-green-400 font-mono">イベントあたり1ms未満</span>
                    </div>
                    <div>
                      <span className="text-gray-400">スループット:</span> <span className="text-green-400 font-mono">毎秒10,000+イベント</span>
                    </div>
                    <div>
                      <span className="text-gray-400">メモリ使用量:</span> <span className="text-green-400 font-mono">50MB未満</span>
                    </div>
                    <div>
                      <span className="text-gray-400">検出ルール:</span> <span className="text-green-400 font-mono">包括的な10ルール</span>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* Call to Action */}
            <section className="mt-16 p-8 bg-gradient-to-r from-purple-800/30 to-blue-800/30 rounded-xl border border-purple-500/30">
              <h2 className="text-2xl font-bold text-white mb-4 text-center">Ready to Secure Your Web Applications?</h2>
              <h3 className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-blue-400 mb-6 text-center">
                Webアプリケーションを保護する準備はできましたか？
              </h3>
              <div className="flex flex-wrap justify-center gap-4">
                <Link
                  href="/docs/NGINX_RULES_REFERENCE.md"
                  className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white font-medium rounded-lg transition-all duration-200 group"
                >
                  📚 Complete Documentation
                  <svg className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
                <Link
                  href="/docs/installation.md"
                  className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-medium rounded-lg transition-all duration-200 group"
                >
                  🚀 Get Started Now
                  <svg className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
                <a
                  href="https://github.com/takaosgb3/falco-plugin-nginx"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-gray-700 to-gray-800 hover:from-gray-600 hover:to-gray-700 text-white font-medium rounded-lg transition-all duration-200 group"
                >
                  💻 View on GitHub
                  <svg className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </a>
              </div>
            </section>
          </div>
        </div>
      </article>

      {/* Related Articles */}
      <section className="pb-16 px-4">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-white mb-6">Related Articles | 関連記事</h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-gradient-to-br from-slate-800/40 to-purple-800/20 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6">
              <h3 className="text-lg font-bold text-white mb-2">Installation & Setup Guide</h3>
              <h4 className="text-sm font-medium text-gray-300 mb-3">インストール・セットアップガイド</h4>
              <p className="text-gray-400 text-sm mb-4">Complete step-by-step guide to install and configure Falco Nginx Plugin in your environment.</p>
              <Link href="/docs/installation.md" className="text-purple-400 hover:text-purple-300 font-medium text-sm">
                Read More →
              </Link>
            </div>
            <div className="bg-gradient-to-br from-slate-800/40 to-purple-800/20 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6">
              <h3 className="text-lg font-bold text-white mb-2">Troubleshooting Guide</h3>
              <h4 className="text-sm font-medium text-gray-300 mb-3">トラブルシューティングガイド</h4>
              <p className="text-gray-400 text-sm mb-4">Common issues and solutions when working with Falco Nginx Plugin in production environments.</p>
              <Link href="/docs/TROUBLESHOOTING.md" className="text-purple-400 hover:text-purple-300 font-medium text-sm">
                Read More →
              </Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}