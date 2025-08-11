import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ArrowRight, Shield, Zap, Target, ChevronRight, CheckCircle, TrendingDown, Clock, BarChart3, GitBranch, Award, Sparkles } from "lucide-react"

export default function Home() {
  return (
    <>
      {/* Hero Section with Gradient Background */}
      <section className="relative overflow-hidden bg-gradient-to-b from-primary/5 via-transparent to-transparent min-h-[90vh] flex items-center">
        {/* Animated Background Mesh */}
        <div className="absolute inset-0 bg-gradient-mesh opacity-30 animate-gradient" />
        
        {/* Floating Elements */}
        <div className="absolute top-20 left-10 w-72 h-72 bg-primary/10 rounded-full filter blur-3xl animate-pulse" />
        <div className="absolute bottom-20 right-10 w-96 h-96 bg-accent/10 rounded-full filter blur-3xl animate-pulse delay-1000" />
        
        <div className="container relative mx-auto px-4 sm:px-6 lg:px-8 py-24">
          <div className="mx-auto max-w-5xl text-center">
            {/* Logo */}
            <div className="mb-8 inline-block">
              <Image 
                src="/falcoya-logo.png" 
                alt="FALCOYA" 
                width={120} 
                height={120} 
                className="w-24 h-24 md:w-32 md:h-32"
              />
            </div>
            
            {/* Main Heading with Gradient */}
            <h1 className="font-heading text-5xl md:text-7xl font-bold tracking-tight mb-6">
              <span className="gradient-text">Craft more than detect.</span>
            </h1>
            
            {/* Subtitle */}
            <p className="text-xl md:text-2xl text-muted-foreground mb-4 font-medium">
              小さな行動で、大きく静かな安全を。
            </p>
            
            <p className="text-lg text-muted-foreground max-w-3xl mx-auto mb-12">
              Falco屋は、誤検知を<span className="font-semibold text-foreground">92%削減</span>し、
              本物の脅威を見逃さない<br className="hidden md:block" />
              次世代のセキュリティ監視を実現します。
            </p>
            
            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Link href="/proof-cards">
                <Button 
                  size="lg" 
                  className="bg-gradient-to-r from-primary to-secondary text-white border-0 hover:shadow-lg hover:scale-105 transition-all duration-300 px-8 py-6 text-lg rounded-full"
                >
                  <Sparkles className="mr-2 h-5 w-5" />
                  実績を見る
                </Button>
              </Link>
              <Link href="/products">
                <Button 
                  variant="outline" 
                  size="lg" 
                  className="rounded-full px-8 py-6 text-lg hover:bg-muted transition-all duration-300"
                >
                  料金プランを見る
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Metrics Section with Glass Effect */}
      <section className="py-20 relative">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            <div className="glass rounded-2xl p-8 text-center hover:shadow-xl transition-all duration-300 hover:-translate-y-1">
              <TrendingDown className="w-12 h-12 text-primary mx-auto mb-4" />
              <div className="text-5xl font-bold gradient-text mb-2">-92%</div>
              <div className="text-sm font-medium text-muted-foreground uppercase tracking-wider">誤検知削減率</div>
              <p className="text-sm text-muted-foreground mt-2">業界最高水準の精度</p>
            </div>
            <div className="glass rounded-2xl p-8 text-center hover:shadow-xl transition-all duration-300 hover:-translate-y-1">
              <Clock className="w-12 h-12 text-primary mx-auto mb-4" />
              <div className="text-5xl font-bold gradient-text mb-2">15秒</div>
              <div className="text-sm font-medium text-muted-foreground uppercase tracking-wider">MTTD P95</div>
              <p className="text-sm text-muted-foreground mt-2">脅威の即座検出</p>
            </div>
            <div className="glass rounded-2xl p-8 text-center hover:shadow-xl transition-all duration-300 hover:-translate-y-1">
              <BarChart3 className="w-12 h-12 text-primary mx-auto mb-4" />
              <div className="text-5xl font-bold gradient-text mb-2">99.9%</div>
              <div className="text-sm font-medium text-muted-foreground uppercase tracking-wider">SLO達成率</div>
              <p className="text-sm text-muted-foreground mt-2">安定した運用保証</p>
            </div>
          </div>
        </div>
      </section>

      {/* Featured Proof Cards */}
      <section className="py-20 bg-gradient-to-b from-muted/30 to-transparent">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <span className="text-primary font-semibold text-sm uppercase tracking-wider">PROOF CARDS</span>
            <h2 className="font-heading text-4xl md:text-5xl font-bold mt-4 mb-6">
              実績で語る、数字で証明する
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              大手企業での導入実績と改善結果をご覧ください
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3 max-w-6xl mx-auto">
            {/* Proof Card 1 */}
            <Card className="group hover:shadow-2xl transition-all duration-300 border-0 bg-white/80 backdrop-blur hover:-translate-y-2">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-primary bg-primary/10 px-3 py-1 rounded-full">AWS EKS</span>
                  <Award className="w-5 h-5 text-amber-500" />
                </div>
                <CardTitle className="text-xl">EKS環境のノイズ削減</CardTitle>
                <CardDescription className="text-base">大手ECサイト様</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 mb-6">
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <span className="text-sm font-medium">誤検知率</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground line-through">78%</span>
                      <ArrowRight className="w-4 h-4 text-primary" />
                      <span className="text-sm font-bold text-primary">3%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <span className="text-sm font-medium">MTTD</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground line-through">5分</span>
                      <ArrowRight className="w-4 h-4 text-primary" />
                      <span className="text-sm font-bold text-primary">30秒</span>
                    </div>
                  </div>
                </div>
                <Link href="/proof-cards/eks-noise-reduction">
                  <Button variant="ghost" className="w-full group-hover:bg-primary group-hover:text-white transition-all duration-300">
                    詳細を見る <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Proof Card 2 */}
            <Card className="group hover:shadow-2xl transition-all duration-300 border-0 bg-white/80 backdrop-blur hover:-translate-y-2">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-primary bg-primary/10 px-3 py-1 rounded-full">Google GKE</span>
                  <Award className="w-5 h-5 text-amber-500" />
                </div>
                <CardTitle className="text-xl">GKE検知強化</CardTitle>
                <CardDescription className="text-base">金融サービス様</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 mb-6">
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <span className="text-sm font-medium">誤検知率</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground line-through">65%</span>
                      <ArrowRight className="w-4 h-4 text-primary" />
                      <span className="text-sm font-bold text-primary">8%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <span className="text-sm font-medium">インシデント</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-primary">-85%</span>
                    </div>
                  </div>
                </div>
                <Link href="/proof-cards/gke-detection">
                  <Button variant="ghost" className="w-full group-hover:bg-primary group-hover:text-white transition-all duration-300">
                    詳細を見る <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Proof Card 3 */}
            <Card className="group hover:shadow-2xl transition-all duration-300 border-0 bg-white/80 backdrop-blur hover:-translate-y-2">
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-primary bg-primary/10 px-3 py-1 rounded-full">On-Premise</span>
                  <Award className="w-5 h-5 text-amber-500" />
                </div>
                <CardTitle className="text-xl">オンプレミス移行</CardTitle>
                <CardDescription className="text-base">製造業様</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 mb-6">
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <span className="text-sm font-medium">誤検知率</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground line-through">82%</span>
                      <ArrowRight className="w-4 h-4 text-primary" />
                      <span className="text-sm font-bold text-primary">5%</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <span className="text-sm font-medium">運用工数</span>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-primary">-70%</span>
                    </div>
                  </div>
                </div>
                <Link href="/proof-cards/onprem-migration">
                  <Button variant="ghost" className="w-full group-hover:bg-primary group-hover:text-white transition-all duration-300">
                    詳細を見る <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>

          <div className="mt-16 text-center">
            <Link href="/proof-cards">
              <Button 
                size="lg" 
                variant="outline"
                className="rounded-full px-8 py-6 text-lg hover:bg-primary hover:text-white hover:border-primary transition-all duration-300"
              >
                すべての実績を見る
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* How We Work - Modern Grid */}
      <section className="py-20 relative">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <span className="text-primary font-semibold text-sm uppercase tracking-wider">OUR APPROACH</span>
            <h2 className="font-heading text-4xl md:text-5xl font-bold mt-4 mb-6">
              3ステップで実現する静かな安全
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              シンプルで確実なアプローチ
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-3 max-w-5xl mx-auto">
            <div className="group relative">
              <div className="absolute inset-0 bg-gradient-to-br from-primary to-secondary rounded-2xl opacity-0 group-hover:opacity-10 transition-opacity duration-300" />
              <div className="relative p-8 rounded-2xl border border-border hover:border-primary transition-all duration-300">
                <div className="w-16 h-16 rounded-xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center mb-6">
                  <Shield className="w-8 h-8 text-white" />
                </div>
                <span className="text-5xl font-bold text-muted-foreground/20 absolute top-8 right-8">01</span>
                <h3 className="text-2xl font-bold mb-3">Rule</h3>
                <p className="text-muted-foreground leading-relaxed">
                  ノイズの少ないルール設計で、
                  環境に最適化された検出ロジックを構築
                </p>
              </div>
            </div>

            <div className="group relative">
              <div className="absolute inset-0 bg-gradient-to-br from-primary to-secondary rounded-2xl opacity-0 group-hover:opacity-10 transition-opacity duration-300" />
              <div className="relative p-8 rounded-2xl border border-border hover:border-primary transition-all duration-300">
                <div className="w-16 h-16 rounded-xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center mb-6">
                  <Zap className="w-8 h-8 text-white" />
                </div>
                <span className="text-5xl font-bold text-muted-foreground/20 absolute top-8 right-8">02</span>
                <h3 className="text-2xl font-bold mb-3">Test</h3>
                <p className="text-muted-foreground leading-relaxed">
                  実環境での攻撃シミュレーションと
                  継続的な検証・チューニング
                </p>
              </div>
            </div>

            <div className="group relative">
              <div className="absolute inset-0 bg-gradient-to-br from-primary to-secondary rounded-2xl opacity-0 group-hover:opacity-10 transition-opacity duration-300" />
              <div className="relative p-8 rounded-2xl border border-border hover:border-primary transition-all duration-300">
                <div className="w-16 h-16 rounded-xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center mb-6">
                  <Target className="w-8 h-8 text-white" />
                </div>
                <span className="text-5xl font-bold text-muted-foreground/20 absolute top-8 right-8">03</span>
                <h3 className="text-2xl font-bold mb-3">SLO</h3>
                <p className="text-muted-foreground leading-relaxed">
                  継続的な改善とSLO保証で、
                  メトリクスベースの品質管理
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Cards - Premium Design */}
      <section className="py-20 bg-gradient-to-b from-transparent to-muted/30">
        <div className="container mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <span className="text-primary font-semibold text-sm uppercase tracking-wider">PRICING</span>
            <h2 className="font-heading text-4xl md:text-5xl font-bold mt-4 mb-6">
              あなたのチームに最適なプラン
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              規模と要件に合わせて選べる3つのプラン
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-3 max-w-6xl mx-auto">
            {/* Starter Plan */}
            <Card className="relative border-2 hover:border-primary transition-all duration-300 hover:shadow-xl">
              <CardHeader className="pb-8">
                <CardTitle className="text-2xl">Starter</CardTitle>
                <CardDescription className="text-base">小規模チーム向け</CardDescription>
                <div className="mt-6">
                  <span className="text-5xl font-bold">¥50,000</span>
                  <span className="text-muted-foreground ml-2">/月〜</span>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <ul className="space-y-4">
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">通知テンプレート（Slack/Teams対応）</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">CI/CDハーネス</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">基本サポート（平日9-18時）</span>
                  </li>
                </ul>
                <Link href="/products/starter" className="block">
                  <Button variant="outline" className="w-full rounded-full hover:bg-primary hover:text-white transition-all duration-300">
                    14日間無料トライアル
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Pro Plan - Featured */}
            <Card className="relative border-2 border-primary shadow-xl scale-105">
              <div className="absolute -top-4 left-1/2 -translate-x-1/2">
                <span className="bg-gradient-to-r from-primary to-secondary text-white text-sm font-semibold px-4 py-1 rounded-full">
                  MOST POPULAR
                </span>
              </div>
              <CardHeader className="pb-8 pt-8">
                <CardTitle className="text-2xl">Pro</CardTitle>
                <CardDescription className="text-base">成長企業向け</CardDescription>
                <div className="mt-6">
                  <span className="text-5xl font-bold gradient-text">要相談</span>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <ul className="space-y-4">
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">ルールチューニング代行</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">カスタムプラグイン開発</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">攻撃シナリオ再現テスト</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">24/7 優先サポート</span>
                  </li>
                </ul>
                <Link href="/products/pro" className="block">
                  <Button className="w-full bg-gradient-to-r from-primary to-secondary text-white border-0 hover:shadow-lg hover:scale-105 transition-all duration-300 rounded-full">
                    見積もりを依頼
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Enterprise Plan */}
            <Card className="relative border-2 hover:border-primary transition-all duration-300 hover:shadow-xl">
              <CardHeader className="pb-8">
                <CardTitle className="text-2xl">Enterprise</CardTitle>
                <CardDescription className="text-base">大規模組織向け</CardDescription>
                <div className="mt-6">
                  <span className="text-5xl font-bold">要相談</span>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <ul className="space-y-4">
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">SLO設計支援</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">定期レビュー（月次）</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">インシデント対応同伴</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                    <span className="text-sm">専任エンジニア配置</span>
                  </li>
                </ul>
                <Link href="/products/enterprise" className="block">
                  <Button variant="outline" className="w-full rounded-full hover:bg-primary hover:text-white transition-all duration-300">
                    エンタープライズ相談
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Guild Section - Community Focus */}
      <section className="py-20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-mesh opacity-20" />
        <div className="container relative mx-auto px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-4xl text-center">
            <span className="text-primary font-semibold text-sm uppercase tracking-wider">COMMUNITY</span>
            <h2 className="font-heading text-4xl md:text-5xl font-bold mt-4 mb-6">
              Guildメンバーシップ
            </h2>
            <p className="text-xl text-muted-foreground mb-12">
              技術力で貢献し、成果で報われるコミュニティ
            </p>
            
            <div className="grid gap-6 md:grid-cols-3 mb-12">
              <div className="glass rounded-2xl p-8 hover:shadow-xl transition-all duration-300">
                <GitBranch className="w-12 h-12 text-primary mx-auto mb-4" />
                <h3 className="text-xl font-bold mb-2">Member</h3>
                <p className="text-sm text-muted-foreground mb-4">PR 1件 or Proof 1件</p>
                <div className="text-xs text-primary font-semibold">Discordアクセス権</div>
              </div>
              
              <div className="glass rounded-2xl p-8 hover:shadow-xl transition-all duration-300">
                <Award className="w-12 h-12 text-secondary mx-auto mb-4" />
                <h3 className="text-xl font-bold mb-2">Artisan</h3>
                <p className="text-sm text-muted-foreground mb-4">PR 5件 or Proof 3件</p>
                <div className="text-xs text-secondary font-semibold">Marketplace出品権</div>
              </div>
              
              <div className="glass rounded-2xl p-8 hover:shadow-xl transition-all duration-300">
                <Sparkles className="w-12 h-12 text-accent mx-auto mb-4" />
                <h3 className="text-xl font-bold mb-2">Master</h3>
                <p className="text-sm text-muted-foreground mb-4">審査通過</p>
                <div className="text-xs text-accent font-semibold">案件アサイン優先権</div>
              </div>
            </div>
            
            <Link href="/guild">
              <Button 
                size="lg"
                variant="outline" 
                className="rounded-full px-8 py-6 text-lg hover:bg-primary hover:text-white hover:border-primary transition-all duration-300"
              >
                Guildについて詳しく見る
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* CTA Section - Gradient Background */}
      <section className="relative py-24 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary via-secondary to-accent opacity-90" />
        <div className="container relative mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto">
            <h2 className="font-heading text-4xl md:text-5xl font-bold text-white mb-6">
              静かな安全を、今すぐ実現
            </h2>
            <p className="text-xl text-white/90 mb-12">
              まずはDiscordで最新ルールを受け取ることから始めましょう
            </p>
            <div className="flex flex-col sm:flex-row gap-6 justify-center">
              <Link
                href="https://discord.gg/falcoya"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button 
                  size="lg" 
                  className="bg-white text-primary hover:bg-gray-100 rounded-full px-8 py-6 text-lg font-semibold transition-all duration-300 hover:scale-105"
                >
                  <svg className="w-6 h-6 mr-2" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515a.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0a12.64 12.64 0 0 0-.617-1.25a.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057a19.9 19.9 0 0 0 5.993 3.03a.078.078 0 0 0 .084-.028a14.09 14.09 0 0 0 1.226-1.994a.076.076 0 0 0-.041-.106a13.107 13.107 0 0 1-1.872-.892a.077.077 0 0 1-.008-.128a10.2 10.2 0 0 0 .372-.292a.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127a12.299 12.299 0 0 1-1.873.892a.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028a19.839 19.839 0 0 0 6.002-3.03a.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419c0-1.333.956-2.419 2.157-2.419c1.21 0 2.176 1.096 2.157 2.42c0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419c0-1.333.955-2.419 2.157-2.419c1.21 0 2.176 1.096 2.157 2.42c0 1.333-.946 2.418-2.157 2.418z"/>
                  </svg>
                  Discordで最新ルールを受け取る
                </Button>
              </Link>
              <Link href="/contact">
                <Button 
                  size="lg" 
                  variant="outline" 
                  className="border-2 border-white text-white hover:bg-white hover:text-primary rounded-full px-8 py-6 text-lg font-semibold transition-all duration-300"
                >
                  導入について相談する
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>
    </>
  )
}