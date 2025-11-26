import base64
import json
import os
from datetime import datetime

# Carrega .env para testes locais
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from gemini_analyzer import GeminiSecurityAnalyzer
from audit_parser import parse_audit_log, is_security_relevant, get_change_summary
from email_sender import EmailAlertSender


# Inicializa componentes
analyzer = GeminiSecurityAnalyzer()
email_sender = EmailAlertSender()


def process_infra_change(event, context):
    """Cloud Function principal - trigger Pub/Sub"""
    
    print(f"📥 Evento recebido: {context.event_id}")
    
    # 1. Decodifica mensagem
    try:
        data = base64.b64decode(event['data']).decode('utf-8')
        log_entry = json.loads(data)
    except Exception as e:
        print(f"❌ Erro decodificando: {e}")
        return {"error": str(e)}
    
    # 2. Parseia log
    change_info = parse_audit_log(log_entry)
    print(f"🔍 {get_change_summary(change_info)}")
    
    # 3. Filtra relevância
    if not is_security_relevant(change_info):
        print("⏭️ Não relevante, ignorando")
        return {"status": "ignored"}
    
    # 4. Check rápido
    quick = analyzer.quick_risk_check(
        change_info['resource']['method'],
        change_info.get('request', {})
    )
    if quick:
        print(f"⚡ Alerta rápido: {quick}")
    
    # 5. Análise Gemini
    print("🤖 Analisando com Gemini...")
    result = analyzer.analyze_change(change_info)
    
    if result['success']:
        analysis = result['analysis']
    else:
        print(f"⚠️ Erro Gemini: {result.get('error')}")
        analysis = {
            "risco": quick['risco'] if quick else "MEDIO",
            "vulnerabilidades": [quick['alerta_rapido']] if quick else [],
            "explicacao": "Análise automática falhou",
            "acao_recomendada": "REVISAR"
        }
    
    risco = analysis.get('risco', 'MEDIO')
    print(f"📊 Risco: {risco}")
    
    # 6. Envia email se necessário
    if risco in ['CRITICO', 'ALTO', 'MEDIO']:
        print("📧 Enviando alerta por email...")
        email_sender.send_alert(change_info, analysis)
    
    return {"status": "ok", "risco": risco}


# ===== TESTE LOCAL =====
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🧪 TESTE LOCAL DO SECURITY BOT")
    print("="*60 + "\n")
    
    # Simula log de firewall perigosa
    test_log = {
        "protoPayload": {
            "authenticationInfo": {"principalEmail": "dev@empresa.com"},
            "requestMetadata": {"callerIp": "203.0.113.50"},
            "methodName": "compute.firewalls.insert",
            "resourceName": "projects/meu-projeto/global/firewalls/allow-ssh-public",
            "request": {
                "name": "allow-ssh-public",
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "direction": "INGRESS"
            }
        },
        "resource": {
            "type": "gce_firewall_rule",
            "labels": {"project_id": "meu-projeto"}
        },
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    # Simula evento Pub/Sub
    mock_event = {
        "data": base64.b64encode(json.dumps(test_log).encode()).decode()
    }
    
    class MockContext:
        event_id = "test-local-123"
    
    # Executa
    result = process_infra_change(mock_event, MockContext())
    print(f"\n✅ Resultado: {json.dumps(result, indent=2)}")