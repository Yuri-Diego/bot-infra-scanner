import google.generativeai as genai
import json
import os


class GeminiSecurityAnalyzer:
    def __init__(self, api_key: str = None):
        api_key = api_key or os.environ.get("GEMINI_API_KEY")
        
        if not api_key:
            raise ValueError("GEMINI_API_KEY não configurada")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash')
    
    def analyze_change(self, change_info: dict) -> dict:
        """Analisa mudança com Gemini"""
        
        prompt = f"""Você é um especialista em segurança do Google Cloud.
Analise esta alteração e responda APENAS com JSON válido.

REGRAS DE CLASSIFICAÇÃO:
- CRITICO: sourceRanges contém 0.0.0.0/0 com portas sensíveis (22, 3389, 3306, 5432, 27017)
- ALTO: sourceRanges contém 0.0.0.0/0 com qualquer porta
- MEDIO: Alterações em IAM ou permissões amplas
- BAIXO: Regras com IPs específicos ou redes internas (10.x, 172.16.x, 192.168.x)
- NENHUM: Alterações cosméticas ou baixo impacto

IMPORTANTE: Redes internas (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) são SEGURAS e devem ser classificadas como BAIXO ou NENHUM.

Responda com JSON:
{{
    "risco": "CRITICO|ALTO|MEDIO|BAIXO|NENHUM",
    "categoria": "rede|iam|storage|compute|outro",
    "vulnerabilidades": ["lista de problemas encontrados"],
    "acao_recomendada": "APROVAR|REVISAR|REVERTER",
    "explicacao": "explicação do impacto",
    "remediacao": "passos para corrigir"
}}

ALTERAÇÃO:
- Usuário: {change_info.get('actor', {}).get('email')}
- IP: {change_info.get('actor', {}).get('ip')}
- Recurso: {change_info.get('resource', {}).get('name')}
- Operação: {change_info.get('resource', {}).get('method')}
- Timestamp: {change_info.get('timestamp')}

DETALHES:
{json.dumps(change_info.get('request', {}), indent=2, default=str)[:3000]}

Responda apenas o JSON, sem markdown."""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            
            # Remove marcadores de código se houver
            if text.startswith('```'):
                text = text.split('\n', 1)[1].rsplit('```', 1)[0]
            
            return {"success": True, "analysis": json.loads(text)}
            
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"JSON inválido: {e}", "raw": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def quick_risk_check(self, method: str, request_data: dict) -> dict:
        """Check rápido sem API"""
        
        patterns = [
            ('0.0.0.0/0', 'CRITICO', 'Regra aberta para internet'),
            ('allUsers', 'CRITICO', 'Acesso público'),
            ('allAuthenticatedUsers', 'ALTO', 'Acesso para qualquer usuário Google'),
            ('roles/owner', 'ALTO', 'Role Owner atribuída'),
        ]
        
        request_str = json.dumps(request_data, default=str)
        
        for pattern, severity, message in patterns:
            if pattern in request_str:
                return {"risco": severity, "alerta_rapido": message}
        
        return None