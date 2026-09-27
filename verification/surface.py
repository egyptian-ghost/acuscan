#!/usr/bin/env python3
"""Verification 2.0 passive/low-impact application surface checks.
Runs once per URL rather than once per parameter.
"""
import base64, json, re, time
from urllib.parse import urljoin, urlparse
from .models import VerifiedFinding, VerificationEvidence, VerificationStep

class SurfaceVerifier:
    def __init__(self, http_client, config=None):
        self.http = http_client; self.config = config or {}

    def _finding(self, title, typ, url, severity, cwe, desc, ev, methods, remediation, extracted=None):
        now=time.time()
        return VerifiedFinding(title=title, vuln_type=typ, severity=severity, url=url,
            verified=True, confidence=ev.confidence, verification_methods=methods,
            description=desc, remediation=remediation, cwe=cwe,
            steps=[VerificationStep(name=m, stage="confirmation", status="passed") for m in methods],
            all_evidence=[ev], extracted_info=extracted or {}, timestamp=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
            reproduction={"method":"GET","url":url,"parameter":"","payload":"","steps":methods},
            verification_timeline=[{"timestamp":__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),"stage":"confirmation","step":m,"status":"passed"} for m in methods],
            key_exchange=ev.exchange)

    def scan(self, url):
        out=[]
        ex=self.http.get(url)
        if not ex or not ex.response_status: return out
        h={k.lower():v for k,v in (ex.response_headers or {}).items()}
        body=ex.response_body or ''
        # CORS: test an untrusted Origin and only report explicit reflection with credentials.
        try:
            cors=self.http.request('OPTIONS',url,headers={'Origin':'https://acuscan.invalid','Access-Control-Request-Method':'GET'})
            ch={k.lower():v for k,v in (cors.response_headers or {}).items()}
            aco=ch.get('access-control-allow-origin',''); acc=ch.get('access-control-allow-credentials','').lower()
            if aco in ('https://acuscan.invalid','*') and acc=='true' and aco!='*':
                ev=VerificationEvidence(type='cors_reflection',title='Credentialed CORS origin reflection',description='The server explicitly reflects an untrusted Origin while allowing credentials.',exchange=cors,confidence=0.92,extracted_data={'allow_origin':aco,'allow_credentials':acc})
                out.append(self._finding('Credentialed CORS Misconfiguration','CORS',url,'high','CWE-942','Untrusted origins can be granted credentialed cross-origin access.',ev,['origin_probe','credential_check'],'Allow only explicit trusted origins and avoid credentials with broad origins.'))
        except Exception: pass
        # Security headers: report only meaningful missing headers on HTML.
        if 'text/html' in h.get('content-type','').lower():
            missing=[x for x in ('content-security-policy','x-content-type-options','referrer-policy') if x not in h]
            if missing:
                ev=VerificationEvidence(type='header_audit',title='Missing security headers',description='Important browser security headers are absent from the observed response.',exchange=ex,confidence=0.86,extracted_data={'missing':missing})
                out.append(self._finding('Missing Security Headers','SECURITY_HEADERS',url,'low','CWE-693','The response omits one or more defense-in-depth security headers.',ev,['header_audit'],'Configure a suitable CSP, X-Content-Type-Options and Referrer-Policy according to application requirements.',{'missing':missing}))
        # OpenAPI / Swagger exposure, low impact GET only.
        candidates=['/openapi.json','/swagger.json','/api-docs','/v3/api-docs','/swagger/v1/swagger.json']
        for path in candidates:
            u=urljoin(url,path)
            try:
                q=self.http.get(u)
                ct=(q.response_headers or {}).get('Content-Type','').lower(); b=q.response_body or ''
                if q.response_status==200 and (('json' in ct and ('openapi' in b.lower() or 'swagger' in b.lower())) or 'openapi' in b[:500].lower()):
                    ev=VerificationEvidence(type='api_schema',title='API schema exposed',description='A machine-readable API description is publicly reachable.',exchange=q,confidence=0.97,extracted_data={'path':path})
                    out.append(self._finding('Public API Documentation','API_SCHEMA',u,'info','CWE-200','An API schema is accessible without authentication.',ev,['schema_probe'],'Restrict API documentation to intended users/environments where appropriate.'))
                    break
            except Exception: pass
        # GraphQL endpoint discovery + harmless schema metadata probe.
        for path in ['/graphql','/api/graphql','/graphql/']:
            u=urljoin(url,path)
            try:
                q=self.http.post(u,json={'query':'query { __typename }'})
                b=q.response_body or ''
                if q.response_status in (200,400) and ('graphql' in b.lower() or 'data' in b.lower() or 'errors' in b.lower()):
                    ev=VerificationEvidence(type='graphql_probe',title='GraphQL endpoint detected',description='A GraphQL-compatible endpoint responded to a harmless __typename probe.',exchange=q,confidence=0.95,extracted_data={'endpoint':u})
                    out.append(self._finding('GraphQL Endpoint Detected','GRAPHQL',u,'info','CWE-200','GraphQL endpoint was identified. Deeper schema and authorization analysis can be enabled for authorized targets.',ev,['graphql_probe'],'Restrict GraphQL introspection and enforce authorization at resolver/field level where appropriate.'))
                    break
            except Exception: pass
        # JWT exposure: detect JWT-shaped tokens in HTML/JSON, decode only metadata (no cracking).
        tokens=set(re.findall(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}', body))
        for tok in list(tokens)[:5]:
            try:
                head,pay,_=tok.split('.')
                hd=json.loads(base64.urlsafe_b64decode(head+'='*((4-len(head)%4)%4)))
                pl=json.loads(base64.urlsafe_b64decode(pay+'='*((4-len(pay)%4)%4)))
                ev=VerificationEvidence(type='jwt_exposure',title='JWT-like token exposed in response',description='A JWT-shaped token was found in the page response. The scanner decoded header/claims only and did not attempt signature bypass or cracking.',exchange=ex,confidence=0.88,extracted_data={'header':hd,'claims':{k:pl.get(k) for k in ('iss','aud','sub','exp','iat','nbf') if k in pl}})
                out.append(self._finding('JWT Token Exposure','JWT',url,'medium','CWE-200','A JWT-shaped token is exposed in a response body.',ev,['jwt_detection','claim_decode'],'Avoid exposing authentication tokens in HTML or logs; use secure, scoped token transport.',{'header':hd,'claims':pl}))
            except Exception: pass
        return out
