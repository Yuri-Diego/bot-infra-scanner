def parse_audit_log(log_entry: dict) -> dict:
    """Extrai info do Cloud Audit Log"""
    
    proto = log_entry.get('protoPayload', {})
    resource = log_entry.get('resource', {})
    labels = resource.get('labels', {})
    
    return {
        "actor": {
            "email": proto.get('authenticationInfo', {}).get('principalEmail', 'unknown'),
            "ip": proto.get('requestMetadata', {}).get('callerIp', 'unknown'),
        },
        "resource": {
            "type": resource.get('type', 'unknown'),
            "name": proto.get('resourceName', 'unknown'),
            "method": proto.get('methodName', 'unknown'),
        },
        "timestamp": log_entry.get('timestamp', 'unknown'),
        "project": labels.get('project_id', 'unknown'),
        "request": proto.get('request', {}),
    }


def is_security_relevant(change_info: dict) -> bool:
    """Filtra mudanças relevantes"""
    
    method = change_info['resource']['method'].lower()
    
    keywords = ['firewall', 'iam', 'setiampolicy', 'insert', 'create', 
                'update', 'delete', 'patch', 'security', 'ssl']
    
    return any(kw in method for kw in keywords)


def get_change_summary(change_info: dict) -> str:
    """Resumo da mudança"""
    
    actor = change_info['actor']['email']
    resource = change_info['resource']['name'].split('/')[-1]
    method = change_info['resource']['method'].split('.')[-1]
    
    return f"{actor} executou {method} em {resource}"