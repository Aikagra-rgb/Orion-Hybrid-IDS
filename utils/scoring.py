def calculate_threat_score(sig_alert, ml_alert):
    score = 0
    alert_types = []
    
    if sig_alert:
        score += 40
        alert_types.append(sig_alert['type'])
    if ml_alert:
        score += 50
        alert_types.append(ml_alert['type'])
        
    return min(score, 100), " & ".join(alert_types)

def determine_severity(threat_score, reputation_score):
    total = threat_score + reputation_score
    if total > 120: return "Critical"
    elif total > 80: return "High"
    elif total > 50: return "Medium"
    else: return "Low"