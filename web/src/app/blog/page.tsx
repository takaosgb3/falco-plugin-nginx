import { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Blog | FALCOYA - セキュリティエキスパートブログ",
  description: "Falco Nginx Plugin に関する技術ブログ。セキュリティルール解説、実装ガイド、ベストプラクティスを詳細に解説します。",
  keywords: "Falco, Nginx, security rules, web security, blog, セキュリティルール, 技術ブログ",
  openGraph: {
    title: "Blog | FALCOYA - セキュリティエキスパートブログ",
    description: "Falco Nginx Plugin の技術解説とセキュリティベストプラクティス",
    url: "https://falcoya.com/blog",
    siteName: "FALCOYA",
    images: [
      {
        url: "/og-blog-image.png",
        width: 1200,
        height: 630,
      },
    ],
    locale: "ja_JP",
    type: "website",
  },
};

const blogPosts = [
  {
    id: "security-rules-explained",
    title: "Understanding Falco Nginx Plugin Security Rules: A Complete Guide",
    titleJa: "Falco Nginx Plugin セキュリティルール完全解説ガイド",
    description: "A comprehensive guide explaining all 10 security rules in the Falco Nginx Plugin, from SQL injection detection to system monitoring.",
    descriptionJa: "SQLインジェクション検出からシステム監視まで、Falco Nginx Plugin の全10セキュリティルールを包括的に解説します。",
    date: "2025-08-11",
    readTime: "15 minutes",
    readTimeJa: "15分",
    category: "Technical Deep Dive",
    categoryJa: "技術詳細解説",
    tags: ["Security Rules", "Real-time Monitoring", "Web Security", "NGINX"],
    tagsJa: ["セキュリティルール", "リアルタイム監視", "Webセキュリティ", "NGINX"],
    featured: true,
  },
];

export default function BlogPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Hero Section */}
      <section className="pt-24 pb-12 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h1 className="text-5xl md:text-7xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 mb-6">
              Security Expert Blog
            </h1>
            <h2 className="text-3xl md:text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 mb-6">
              セキュリティエキスパートブログ
            </h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto leading-relaxed">
              Real-time web security insights, technical deep-dives, and best practices from the Falco Nginx Plugin development team.
            </p>
            <p className="text-lg text-gray-400 max-w-3xl mx-auto leading-relaxed mt-4">
              Falco Nginx Plugin 開発チームによる、リアルタイムWebセキュリティの洞察、技術詳細解説、ベストプラクティス。
            </p>
          </div>
        </div>
      </section>

      {/* Featured Post */}
      <section className="pb-12 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-white mb-4">Featured Article | 注目記事</h2>
          </div>
          
          {blogPosts
            .filter(post => post.featured)
            .map((post) => (
              <div key={post.id} className="bg-gradient-to-r from-slate-800/50 to-purple-800/30 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-8 mb-8 hover:border-purple-400/40 transition-all duration-300">
                <div className="flex flex-wrap gap-2 mb-4">
                  <span className="px-3 py-1 bg-gradient-to-r from-red-500 to-pink-500 text-white text-sm font-medium rounded-full">
                    Featured | 注目
                  </span>
                  <span className="px-3 py-1 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-sm font-medium rounded-full">
                    {post.category} | {post.categoryJa}
                  </span>
                </div>
                
                <h3 className="text-2xl md:text-3xl font-bold text-white mb-2">
                  {post.title}
                </h3>
                <h4 className="text-xl md:text-2xl font-bold text-gray-300 mb-4">
                  {post.titleJa}
                </h4>
                
                <div className="flex items-center text-gray-400 text-sm mb-4 space-x-4">
                  <span>{post.date}</span>
                  <span>•</span>
                  <span>{post.readTime} | {post.readTimeJa}</span>
                </div>
                
                <p className="text-gray-300 mb-2 leading-relaxed">
                  {post.description}
                </p>
                <p className="text-gray-400 mb-6 leading-relaxed">
                  {post.descriptionJa}
                </p>
                
                <div className="flex flex-wrap gap-2 mb-6">
                  {post.tags.map((tag, index) => (
                    <span key={tag} className="px-2 py-1 bg-slate-700 text-gray-300 text-xs rounded">
                      {tag}
                      {post.tagsJa[index] && (
                        <span className="text-gray-500"> | {post.tagsJa[index]}</span>
                      )}
                    </span>
                  ))}
                </div>
                
                <Link
                  href={`/blog/${post.id}`}
                  className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white font-medium rounded-lg transition-all duration-200 group"
                >
                  Read Article | 記事を読む
                  <svg
                    className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform duration-200"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
              </div>
          ))}
        </div>
      </section>

      {/* Recent Posts */}
      <section className="pb-16 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-white mb-4">Latest Articles | 最新記事</h2>
          </div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {blogPosts.map((post) => (
              <div key={post.id} className="bg-gradient-to-br from-slate-800/40 to-purple-800/20 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 hover:border-purple-500/40 transition-all duration-300">
                <div className="flex flex-wrap gap-2 mb-4">
                  {post.featured && (
                    <span className="px-2 py-1 bg-gradient-to-r from-red-500 to-pink-500 text-white text-xs font-medium rounded-full">
                      Featured | 注目
                    </span>
                  )}
                  <span className="px-2 py-1 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-xs font-medium rounded-full">
                    {post.category} | {post.categoryJa}
                  </span>
                </div>
                
                <h3 className="text-lg font-bold text-white mb-2">
                  {post.title}
                </h3>
                <h4 className="text-sm font-medium text-gray-300 mb-3">
                  {post.titleJa}
                </h4>
                
                <div className="flex items-center text-gray-400 text-xs mb-3 space-x-2">
                  <span>{post.date}</span>
                  <span>•</span>
                  <span>{post.readTime} | {post.readTimeJa}</span>
                </div>
                
                <p className="text-gray-400 text-sm mb-4 line-clamp-3">
                  {post.descriptionJa}
                </p>
                
                <div className="flex flex-wrap gap-1 mb-4">
                  {post.tags.slice(0, 2).map((tag, index) => (
                    <span key={tag} className="px-2 py-1 bg-slate-700 text-gray-300 text-xs rounded">
                      {tag}
                    </span>
                  ))}
                  {post.tags.length > 2 && (
                    <span className="px-2 py-1 bg-slate-700 text-gray-300 text-xs rounded">
                      +{post.tags.length - 2} more
                    </span>
                  )}
                </div>
                
                <Link
                  href={`/blog/${post.id}`}
                  className="inline-flex items-center text-purple-400 hover:text-purple-300 font-medium text-sm group"
                >
                  Read More | 続きを読む
                  <svg
                    className="ml-1 w-3 h-3 group-hover:translate-x-1 transition-transform duration-200"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Newsletter Section */}
      <section className="pb-16 px-4">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gradient-to-r from-purple-800/30 to-blue-800/30 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-8 text-center">
            <h2 className="text-2xl md:text-3xl font-bold text-white mb-4">
              Stay Updated | 最新情報をお届け
            </h2>
            <p className="text-gray-300 mb-6 max-w-2xl mx-auto">
              Get the latest security insights, plugin updates, and technical deep-dives delivered to your inbox.
            </p>
            <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
              最新のセキュリティインサイト、プラグインアップデート、技術詳細解説をお受け取りください。
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center max-w-md mx-auto">
              <input
                type="email"
                placeholder="your@email.com"
                className="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-500 transition-colors duration-200"
              />
              <button className="px-6 py-2 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white font-medium rounded-lg transition-all duration-200">
                Subscribe | 登録
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}