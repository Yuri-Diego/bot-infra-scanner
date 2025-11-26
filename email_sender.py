import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os


class EmailAlertSender:
    def __init__(self):
        self.smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.environ.get("SMTP_PORT", 587))
        self.smtp_user = os.environ.get("SMTP_USER")
        self.smtp_password = os.environ.get("SMTP_PASSWORD")
        self.from_email = os.environ.get("FROM_EMAIL", self.smtp_user)
        
        # Lista de emails para receber alertas
        alert_emails = os.environ.get("ALERT_EMAILS", "")
        self.to_emails = [e.strip() for e in alert_emails.split(",") if e.strip()]
    
    def send_alert(self, change_info: dict, analysis: dict) -> bool:
        """Envia alerta por email via Gmail"""
        
        # Valida configuração
        if not self.smtp_user or not self.smtp_password:
            print("❌ SMTP_USER ou SMTP_PASSWORD não configurados")
            return False
        
        if not self.to_emails:
            print("❌ ALERT_EMAILS não configurado")
            return False
        
        risco = analysis.get("risco", "MEDIO")
        recurso = change_info['resource']['name'].split('/')[-1]
        
        # Assunto do email
        subject = f"[{risco}] Alerta GCP - {recurso}"
        
        # Corpo do email
        html_body = self._build_html_body(change_info, analysis)
        text_body = self._build_text_body(change_info, analysis)
        
        try:
            # Cria mensagem multipart
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            
            # Anexa versões texto e HTML
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
            
            # Conecta e envia
            print(f"📧 Conectando ao {self.smtp_host}:{self.smtp_port}...")
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()  # Segurança TLS
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, self.to_emails, msg.as_string())
            
            print(f"✅ Email enviado para: {', '.join(self.to_emails)}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            print("❌ Erro de autenticação. Verifique email e senha de app.")
            return False
        except Exception as e:
            print(f"❌ Erro ao enviar email: {e}")
            return False
    
    def _build_html_body(self, change_info: dict, analysis: dict) -> str:
        """Monta email HTML bonito"""
        
        risco = analysis.get("risco", "MEDIO")
        
        # Cores por risco
        risk_colors = {
            "CRITICO": "#dc3545",
            "ALTO": "#fd7e14",
            "MEDIO": "#ffc107",
            "BAIXO": "#17a2b8",
            "NENHUM": "#28a745"
        }
        color = risk_colors.get(risco, "#6c757d")
        
        # Emojis por risco
        risk_emoji = {
            "CRITICO": "🚨",
            "ALTO": "⚠️",
            "MEDIO": "🔶",
            "BAIXO": "ℹ️",
            "NENHUM": "✅"
        }
        emoji = risk_emoji.get(risco, "🔍")
        
        # Vulnerabilidades
        vulns = analysis.get("vulnerabilidades", [])
        vulns_html = "".join([f"<li style='margin: 5px 0;'>{v}</li>" for v in vulns])
        vulns_section = f"<ul style='margin: 10px 0; padding-left: 20px;'>{vulns_html}</ul>" if vulns else "<p style='color: #28a745;'>✅ Nenhuma vulnerabilidade identificada</p>"
        
        # Remediação
        remediacao = analysis.get("remediacao", "")
        remediacao_section = f"""
            <div style="background: #e7f3ff; padding: 15px; border-radius: 8px; margin-top: 20px; border-left: 4px solid #0066cc;">
                <h3 style="margin: 0 0 10px 0; color: #0066cc;">🔧 Remediação Sugerida</h3>
                <p style="margin: 0; white-space: pre-wrap;">{remediacao}</p>
            </div>
        """ if remediacao else ""
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f0f2f5;">
    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        
        <!-- Header -->
        <div style="background: {color}; color: white; padding: 25px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">{emoji} Alerta de Segurança GCP</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9; font-size: 18px;">Risco: {risco}</p>
        </div>
        
        <!-- Conteúdo -->
        <div style="padding: 25px;">
            
            <!-- Quem -->
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                <h3 style="margin: 0 0 10px 0; color: #333;">👤 Quem fez a alteração</h3>
                <table style="width: 100%;">
                    <tr>
                        <td style="padding: 5px 0; color: #666;">Email:</td>
                        <td style="padding: 5px 0; font-weight: bold;">{change_info['actor']['email']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px 0; color: #666;">IP:</td>
                        <td style="padding: 5px 0; font-family: monospace;">{change_info['actor']['ip']}</td>
                    </tr>
                </table>
            </div>
            
            <!-- O que -->
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                <h3 style="margin: 0 0 10px 0; color: #333;">📦 O que foi alterado</h3>
                <table style="width: 100%;">
                    <tr>
                        <td style="padding: 5px 0; color: #666;">Recurso:</td>
                        <td style="padding: 5px 0; font-family: monospace; word-break: break-all;">{change_info['resource']['name']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px 0; color: #666;">Operação:</td>
                        <td style="padding: 5px 0;">{change_info['resource']['method']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px 0; color: #666;">Projeto:</td>
                        <td style="padding: 5px 0;">{change_info.get('project', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px 0; color: #666;">Horário:</td>
                        <td style="padding: 5px 0;">{change_info['timestamp']}</td>
                    </tr>
                </table>
            </div>
            
            <!-- Vulnerabilidades -->
            <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #ffc107;">
                <h3 style="margin: 0 0 10px 0; color: #856404;">🔍 Vulnerabilidades</h3>
                {vulns_section}
            </div>
            
            <!-- Análise -->
            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                <h3 style="margin: 0 0 10px 0; color: #333;">📋 Análise</h3>
                <p style="margin: 0; line-height: 1.6;">{analysis.get('explicacao', 'N/A')}</p>
            </div>
            
            <!-- Ação recomendada -->
            <div style="text-align: center; margin: 20px 0;">
                <span style="display: inline-block; padding: 12px 24px; background: {color}; color: white; border-radius: 6px; font-weight: bold; font-size: 16px;">
                    🛠️ Ação: {analysis.get('acao_recomendada', 'REVISAR')}
                </span>
            </div>
            
            {remediacao_section}
            
        </div>
        
        <!-- Footer -->
        <div style="background: #f8f9fa; padding: 15px; text-align: center; color: #666; font-size: 12px;">
            GCP Security Scanner | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _build_text_body(self, change_info: dict, analysis: dict) -> str:
        """Versão texto do email (fallback)"""
        
        vulns = analysis.get("vulnerabilidades", [])
        vulns_text = "\n".join([f"  • {v}" for v in vulns]) if vulns else "  ✅ Nenhuma"
        
        return f"""
{'='*60}
🔒 ALERTA DE SEGURANÇA GCP - Risco {analysis.get('risco', 'MEDIO')}
{'='*60}

👤 QUEM FEZ A ALTERAÇÃO
   Email: {change_info['actor']['email']}
   IP: {change_info['actor']['ip']}

📦 O QUE FOI ALTERADO
   Recurso: {change_info['resource']['name']}
   Operação: {change_info['resource']['method']}
   Projeto: {change_info.get('project', 'N/A')}
   Horário: {change_info['timestamp']}

🔍 VULNERABILIDADES
{vulns_text}

📋 ANÁLISE
   {analysis.get('explicacao', 'N/A')}

🛠️ AÇÃO RECOMENDADA: {analysis.get('acao_recomendada', 'REVISAR')}

🔧 REMEDIAÇÃO
   {analysis.get('remediacao', 'N/A')}

{'='*60}
GCP Security Scanner | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
"""