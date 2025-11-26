# test_local.py
import os
from gemini_analyzer import GeminiSecurityAnalyzer
from audit_parser import parse_audit_log, is_security_relevant

def test_analyzer():
    """Testa o analisador localmente"""
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("❌ Configure GEMINI_API_KEY")
        return
    
    analyzer = GeminiSecurityAnalyzer(api_key)
    
    # Cenário 1: Firewall perigosa
    print("\n" + "="*50)
    print("TESTE 1: Firewall aberta para internet")
    print("="*50)
    
    firewall_change = {
        "actor": {"email": "dev@empresa.com", "ip": "189.0.0.1"},
        "resource": {
            "name": "projects/prod/global/firewalls/allow-all",
            "type": "gce_firewall_rule",
            "method": "compute.firewalls.insert"
        },
        "timestamp": "2024-01-15T10:30:00Z",
        "request": {
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22", "3389"]}]
        }
    }
    
    # Check rápido primeiro
    quick = analyzer.quick_risk_check(
        firewall_change['resource']['method'],
        firewall_change['request']
    )
    print(f"Check rápido: {quick}")
    
    # Análise completa
    result = analyzer.analyze_change(firewall_change)
    print(f"Análise Gemini: {result['analysis'] if result['success'] else result['error']}")
    
    # Cenário 2: Bucket público
    print("\n" + "="*50)
    print("TESTE 2: Bucket tornado público")
    print("="*50)
    
    bucket_change = {
        "actor": {"email": "admin@empresa.com", "ip": "10.0.0.5"},
        "resource": {
            "name": "projects/_/buckets/dados-sensiveis",
            "type": "gcs_bucket",
            "method": "storage.setIamPolicy"
        },
        "timestamp": "2024-01-15T11:00:00Z",
        "request": {
            "policy": {
                "bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                ]
            }
        }
    }
    
    result = analyzer.analyze_change(bucket_change)
    print(f"Análise Gemini: {result['analysis'] if result['success'] else result['error']}")


if __name__ == "__main__":
    test_analyzer()