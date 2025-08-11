"use client"

import { useState } from "react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ArrowLeft, Send, CheckCircle, Mail, MessageSquare, Building2, User } from "lucide-react"

type FormData = {
  companyName: string
  name: string
  email: string
  plan: string
  message: string
}

type FormErrors = {
  name?: string
  email?: string
  message?: string
}

export default function ContactPage() {
  const [formData, setFormData] = useState<FormData>({
    companyName: "",
    name: "",
    email: "",
    plan: "none",
    message: "",
  })
  
  const [errors, setErrors] = useState<FormErrors>({})
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSubmitted, setIsSubmitted] = useState(false)

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {}
    
    if (!formData.name.trim()) {
      newErrors.name = "お名前は必須です"
    }
    
    if (!formData.email.trim()) {
      newErrors.email = "メールアドレスは必須です"
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = "有効なメールアドレスを入力してください"
    }
    
    if (!formData.message.trim()) {
      newErrors.message = "お問い合わせ内容は必須です"
    } else if (formData.message.length < 10) {
      newErrors.message = "お問い合わせ内容は10文字以上で入力してください"
    }
    
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }
    
    setIsSubmitting(true)
    
    try {
      // API送信をシミュレート
      const response = await fetch("/api/contact", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      })
      
      if (response.ok) {
        setIsSubmitted(true)
      } else {
        throw new Error("送信に失敗しました")
      }
    } catch (error) {
      console.error("Form submission error:", error)
      alert("送信に失敗しました。もう一度お試しください。")
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({ ...prev, [name]: value }))
    // Clear error when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors(prev => ({ ...prev, [name]: undefined }))
    }
  }

  if (isSubmitted) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4 py-24">
        <Card className="max-w-md w-full text-center">
          <CardHeader className="pb-8">
            <div className="w-20 h-20 rounded-full bg-green-100 flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="w-10 h-10 text-green-600" />
            </div>
            <CardTitle className="text-2xl">送信完了しました</CardTitle>
            <CardDescription className="text-base mt-2">
              お問い合わせありがとうございます
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-muted-foreground">
              2営業日以内に担当者よりご連絡させていただきます。
            </p>
            <p className="text-sm text-muted-foreground">
              送信先: {formData.email}
            </p>
            <Link href="/">
              <Button variant="outline" className="mt-4">
                <ArrowLeft className="mr-2 h-4 w-4" />
                ホームに戻る
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen py-24">
      {/* Header */}
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 mb-12">
        <div className="text-center max-w-3xl mx-auto">
          <span className="text-primary font-semibold text-sm uppercase tracking-wider">CONTACT</span>
          <h1 className="font-heading text-4xl md:text-5xl font-bold mt-4 mb-6">
            お問い合わせ
          </h1>
          <p className="text-xl text-muted-foreground">
            Falcoの導入・改善について、お気軽にご相談ください
          </p>
        </div>
      </div>

      {/* Form Section */}
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-2xl mx-auto">
          <Card>
            <CardHeader>
              <CardTitle>お問い合わせフォーム</CardTitle>
              <CardDescription>
                必須項目（*）をご記入の上、送信してください
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Company Name */}
                <div className="space-y-2">
                  <label htmlFor="companyName" className="text-sm font-medium flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-muted-foreground" />
                    会社名
                  </label>
                  <input
                    type="text"
                    id="companyName"
                    name="companyName"
                    value={formData.companyName}
                    onChange={handleChange}
                    className="w-full px-4 py-2 rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
                    placeholder="株式会社Example"
                  />
                </div>

                {/* Name */}
                <div className="space-y-2">
                  <label htmlFor="name" className="text-sm font-medium flex items-center gap-2">
                    <User className="w-4 h-4 text-muted-foreground" />
                    お名前 <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    className={`w-full px-4 py-2 rounded-lg border ${
                      errors.name ? "border-red-500" : "border-border"
                    } focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all`}
                    placeholder="山田 太郎"
                  />
                  {errors.name && (
                    <p className="text-sm text-red-500 mt-1">{errors.name}</p>
                  )}
                </div>

                {/* Email */}
                <div className="space-y-2">
                  <label htmlFor="email" className="text-sm font-medium flex items-center gap-2">
                    <Mail className="w-4 h-4 text-muted-foreground" />
                    メールアドレス <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    className={`w-full px-4 py-2 rounded-lg border ${
                      errors.email ? "border-red-500" : "border-border"
                    } focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all`}
                    placeholder="example@company.com"
                  />
                  {errors.email && (
                    <p className="text-sm text-red-500 mt-1">{errors.email}</p>
                  )}
                </div>

                {/* Plan */}
                <div className="space-y-2">
                  <label htmlFor="plan" className="text-sm font-medium">
                    ご興味のあるプラン
                  </label>
                  <select
                    id="plan"
                    name="plan"
                    value={formData.plan}
                    onChange={handleChange}
                    className="w-full px-4 py-2 rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all bg-white"
                  >
                    <option value="none">選択してください</option>
                    <option value="starter">Starter - ¥50,000/月〜</option>
                    <option value="pro">Pro - 要相談</option>
                    <option value="enterprise">Enterprise - 要相談</option>
                    <option value="custom">カスタムプラン</option>
                  </select>
                </div>

                {/* Message */}
                <div className="space-y-2">
                  <label htmlFor="message" className="text-sm font-medium flex items-center gap-2">
                    <MessageSquare className="w-4 h-4 text-muted-foreground" />
                    お問い合わせ内容 <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    rows={6}
                    className={`w-full px-4 py-2 rounded-lg border ${
                      errors.message ? "border-red-500" : "border-border"
                    } focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all resize-none`}
                    placeholder="Falco導入についてのご相談内容をお聞かせください..."
                  />
                  {errors.message && (
                    <p className="text-sm text-red-500 mt-1">{errors.message}</p>
                  )}
                </div>

                {/* Privacy Notice */}
                <div className="bg-muted/50 rounded-lg p-4">
                  <p className="text-sm text-muted-foreground">
                    送信いただいた情報は、お問い合わせへの対応およびサービスのご案内のみに使用いたします。
                    詳細は<Link href="/legal/privacy" className="text-primary hover:underline">プライバシーポリシー</Link>をご確認ください。
                  </p>
                </div>

                {/* Submit Button */}
                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-gradient-primary text-white border-0 hover:shadow-lg hover:scale-105 transition-all duration-300 rounded-full py-6"
                >
                  {isSubmitting ? (
                    <>送信中...</>
                  ) : (
                    <>
                      <Send className="mr-2 h-4 w-4" />
                      送信する
                    </>
                  )}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Contact Info Cards */}
          <div className="grid gap-6 md:grid-cols-2 mt-12">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">営業時間</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  平日 9:00 - 18:00<br />
                  土日祝日休み
                </p>
                <p className="text-sm text-muted-foreground mt-2">
                  お問い合わせは2営業日以内に返信いたします
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg">その他のお問い合わせ</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  技術的なご質問はDiscordコミュニティへ
                </p>
                <Link href="https://discord.gg/falcoya" target="_blank" rel="noopener noreferrer">
                  <Button variant="outline" className="mt-4 w-full">
                    Discordに参加
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}