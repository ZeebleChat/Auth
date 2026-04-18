use sha2::{Digest, Sha256};

/// Hash a PIN with SHA-256 for storage.
pub fn hash_pin(pin: &str) -> String {
    format!("{:x}", Sha256::digest(pin.as_bytes()))
}

/// Shared HTML email wrapper matching Zeeble's dark UI (bg #212328, accent #6366f1).
/// `title` is the card heading, `body_html` is injected inside the card.
fn build_email_html(title: &str, body_html: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
</head>
<body style="margin:0;padding:0;background:#16181c;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#16181c;padding:40px 16px;">
    <tr>
      <td align="center">
        <table width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;">

          <!-- Logo -->
          <tr>
            <td align="center" style="padding-bottom:24px;">
              <div style="display:inline-block;width:56px;height:56px;border-radius:16px;background:linear-gradient(135deg,#6366f1,#4f46e5);text-align:center;line-height:56px;font-size:24px;font-weight:800;color:#ffffff;letter-spacing:-1px;">Z</div>
            </td>
          </tr>

          <!-- Card -->
          <tr>
            <td style="background:#26282e;border-radius:16px;border:1px solid rgba(255,255,255,0.07);padding:36px 40px;">

              <!-- Heading -->
              <p style="margin:0 0 24px;font-size:22px;font-weight:800;color:#f3f4f6;text-align:center;">{title}</p>

              {body_html}

              <!-- Footer -->
              <p style="margin:28px 0 0;font-size:11px;color:#6b7280;text-align:center;line-height:1.6;">
                If you didn't request this, you can safely ignore this email.<br/>
                Can't find this email? Check your <strong style="color:#9ca3af;">spam or junk folder</strong>.<br/>
                &copy; Zeeble &mdash; <a href="https://zeeble.xyz" style="color:#6366f1;text-decoration:none;">zeeble.xyz</a>
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"#,
        title = title,
        body_html = body_html,
    )
}

/// Send a 6-digit email verification PIN via Resend.
/// Falls back to stdout in dev mode (no RESEND_API_KEY).
pub async fn send_pin_email(to: &str, pin: &str, display_name: &str) -> bool {
    let api_key = match std::env::var("RESEND_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            println!("[EMAIL] Verification PIN for <{}>: {}", to, pin);
            return true;
        }
    };

    let body_html = format!(r#"
      <p style="margin:0 0 8px;font-size:14px;color:#9ca3af;text-align:center;">
        Hey <strong style="color:#f3f4f6;">{name}</strong>, welcome to Zeeble!<br/>
        Use the code below to verify your email address.
      </p>

      <!-- PIN block -->
      <div style="margin:24px 0;background:#212328;border-radius:12px;padding:24px;text-align:center;border:1px solid rgba(99,102,241,0.25);">
        <p style="margin:0 0 6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#6366f1;">Verification Code</p>
        <p style="margin:0;font-size:38px;font-weight:800;letter-spacing:10px;color:#f3f4f6;font-family:'Courier New',monospace;">{pin}</p>
        <p style="margin:10px 0 0;font-size:12px;color:#6b7280;">Expires in 15 minutes</p>
      </div>
    "#,
        name = html_escape(display_name),
        pin = pin,
    );

    let text_body = format!(
        "Hey {name},\n\nYour Zeeble verification code is: {pin}\n\nThis code expires in 15 minutes.\n\nIf you didn't request this, you can safely ignore this email.\n\n— The Zeeble Team",
        name = display_name,
        pin = pin,
    );

    let html = build_email_html("Verify your email", &body_html);

    send_via_resend(&api_key, to, "Verify your Zeeble account", &text_body, &html).await
}

/// Send a password reset PIN email via Resend.
/// Falls back to stdout in dev mode (no RESEND_API_KEY).
pub async fn send_password_reset_email(to: &str, pin: &str, display_name: &str, beam_identity: &str) -> bool {
    let api_key = match std::env::var("RESEND_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            println!("[EMAIL] Password reset PIN for <{}>: {}", to, pin);
            return true;
        }
    };

    let body_html = format!(r#"
      <p style="margin:0 0 16px;font-size:14px;color:#9ca3af;text-align:center;">
        Hey <strong style="color:#f3f4f6;">{name}</strong>,<br/>
        we received a request to reset the password for your Zeeble account.
      </p>

      <!-- Beam identity badge -->
      <div style="margin:0 0 20px;background:#212328;border-radius:10px;padding:12px 16px;text-align:center;border:1px solid rgba(255,255,255,0.07);">
        <p style="margin:0 0 3px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#6b7280;">Beam Identity</p>
        <p style="margin:0;font-size:16px;font-weight:700;color:#f3f4f6;font-family:'Courier New',monospace;">{beam}</p>
      </div>

      <!-- PIN block -->
      <div style="margin:0 0 20px;background:#212328;border-radius:12px;padding:24px;text-align:center;border:1px solid rgba(99,102,241,0.25);">
        <p style="margin:0 0 6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#6366f1;">Reset Code</p>
        <p style="margin:0;font-size:38px;font-weight:800;letter-spacing:10px;color:#f3f4f6;font-family:'Courier New',monospace;">{pin}</p>
        <p style="margin:10px 0 0;font-size:12px;color:#6b7280;">Expires in 15 minutes</p>
      </div>

      <p style="margin:0;font-size:13px;color:#6b7280;text-align:center;">
        Didn't ask for this? Your password has <strong style="color:#f3f4f6;">not</strong> been changed &mdash; you can ignore this email.
      </p>
    "#,
        name = html_escape(display_name),
        beam = html_escape(beam_identity),
        pin = pin,
    );

    let text_body = format!(
        "Hey {name},\n\nWe received a request to reset the password for your Zeeble account.\n\nBeam Identity: {beam}\n\nYour reset code is: {pin}\n\nThis code expires in 15 minutes.\n\nIf you didn't request this, your password has not been changed.\n\n— The Zeeble Team",
        name = display_name,
        beam = beam_identity,
        pin = pin,
    );

    let html = build_email_html("Reset your password", &body_html);

    send_via_resend(&api_key, to, "Reset your Zeeble password", &text_body, &html).await
}

/// Escape the minimal set of HTML special characters needed for display names.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

/// POST to the Resend API with both text and HTML bodies.
async fn send_via_resend(api_key: &str, to: &str, subject: &str, text: &str, html: &str) -> bool {
    let payload = serde_json::json!({
        "from": "noreply@zeeble.xyz",
        "to": [to],
        "subject": subject,
        "text": text,
        "html": html,
    });

    let client = reqwest::Client::new();
    match client
        .post("https://api.resend.com/emails")
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            eprintln!("[EMAIL] Resend error {}: {:?}", resp.status(), resp.text().await);
            false
        }
        Err(e) => {
            eprintln!("[EMAIL] Request failed: {}", e);
            false
        }
    }
}
