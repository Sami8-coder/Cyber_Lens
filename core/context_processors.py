from datetime import datetime

def cyberlens_globals(request):
    return {
        'APP_NAME': 'CyberLens',
        'APP_TAGLINE': 'Explainable Web Security Posture Assessment',
        'CURRENT_YEAR': datetime.now().year,
        'APP_VERSION': '1.0.0',
    }
