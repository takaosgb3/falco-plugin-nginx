import { NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { companyName, name, email, plan, message } = body

    // バリデーション
    if (!name || !email || !message) {
      return NextResponse.json(
        { error: "必須項目が入力されていません" },
        { status: 400 }
      )
    }

    // メール形式チェック
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { error: "有効なメールアドレスを入力してください" },
        { status: 400 }
      )
    }

    // ここで実際の処理を行う
    // 例: SendGrid, Slack通知, データベース保存など
    
    // Slack通知の例（環境変数にWebhook URLを設定）
    const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL
    if (slackWebhookUrl) {
      const slackMessage = {
        text: "新しいお問い合わせがありました",
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: "📬 新規お問い合わせ"
            }
          },
          {
            type: "section",
            fields: [
              {
                type: "mrkdwn",
                text: `*会社名:*\n${companyName || "未記入"}`
              },
              {
                type: "mrkdwn",
                text: `*お名前:*\n${name}`
              },
              {
                type: "mrkdwn",
                text: `*メール:*\n${email}`
              },
              {
                type: "mrkdwn",
                text: `*プラン:*\n${plan === "none" ? "未選択" : plan}`
              }
            ]
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*メッセージ:*\n${message}`
            }
          },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `送信日時: ${new Date().toLocaleString("ja-JP", { timeZone: "Asia/Tokyo" })}`
              }
            ]
          }
        ]
      }

      try {
        await fetch(slackWebhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(slackMessage)
        })
      } catch (error) {
        console.error("Slack notification failed:", error)
        // Slack通知が失敗してもユーザーには成功を返す
      }
    }

    // 成功レスポンス
    return NextResponse.json(
      { 
        success: true,
        message: "お問い合わせを受け付けました" 
      },
      { status: 200 }
    )
    
  } catch (error) {
    console.error("Contact form error:", error)
    return NextResponse.json(
      { error: "サーバーエラーが発生しました" },
      { status: 500 }
    )
  }
}