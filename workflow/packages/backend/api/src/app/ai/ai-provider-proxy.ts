import {
    FastifyPluginAsyncTypebox,
    Type,
} from '@fastify/type-provider-typebox'
import { StatusCodes } from 'http-status-codes'
import { exceptionHandler } from 'workflow-server-shared'
import { EnginePrincipal, PrincipalType } from 'workflow-shared'
import { BillingUsageType, usageService } from '../ee/platform-billing/usage/usage-service'
import { projectService } from '../project/project-service'
import { aiProviderService } from './ai-provider.service'
import dns from 'dns/promises'

// Known AI provider domains that are allowed (allowlist approach)
const ALLOWED_AI_PROVIDER_DOMAINS = [
    'api.openai.com',
    'api.anthropic.com',
    'generativelanguage.googleapis.com',
    'api.cohere.ai',
    'api.mistral.ai',
    'api.together.xyz',
    'api.groq.com',
    'api.perplexity.ai',
    'api.deepseek.com',
    'api.fireworks.ai',
    'api.replicate.com',
    'api.stability.ai',
    'inference.ai.azure.com',
]

// Private IP ranges to block (SSRF protection)
const PRIVATE_IP_RANGES = [
    /^127\./,           // Loopback
    /^10\./,            // Private Class A
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private Class B
    /^192\.168\./,      // Private Class C
    /^169\.254\./,      // Link-local
    /^0\./,             // Current network
    /^::1$/,            // IPv6 loopback
    /^fe80:/,           // IPv6 link-local
    /^fc00:/,           // IPv6 unique local
    /^fd/,              // IPv6 unique local
]

async function isPrivateIP(hostname: string): Promise<boolean> {
    try {
        const addresses = await dns.resolve4(hostname)
        for (const ip of addresses) {
            if (PRIVATE_IP_RANGES.some(pattern => pattern.test(ip))) {
                return true
            }
        }
        return false
    } catch {
        // If DNS resolution fails, block the request for safety
        return true
    }
}

export const proxyController: FastifyPluginAsyncTypebox = async (
    fastify,
    _opts,
) => {
    fastify.all('/:provider/*', ProxyRequest, async (request, reply) => {
        const { provider } = request.params
        const { projectId } = request.principal as EnginePrincipal


        const platformId = await projectService.getPlatformId(projectId)
        console.log('principal proxy', request.principal)
        const aiProvider = await aiProviderService.getOrThrow({
            platformId,
            provider,
            projectId,
        })
        console.log('principal proxy aiProvider', aiProvider);
        const exceededLimit = await usageService(request.log).aiTokensExceededLimit(projectId, 0)
        if (exceededLimit) {
            return reply.code(StatusCodes.PAYMENT_REQUIRED).send(
                makeOpenAiResponse(
                    'You have exceeded your AI tokens limit for this project.',
                    'ai_tokens_limit_exceeded',
                    {},
                ),
            )
        }

        const url = buildUrl(aiProvider.baseUrl, request.params['*'])
        
        // SSRF protection: Validate URL before making request
        await validateUrlForSSRF(url)
        
        try {
            const cleanHeaders = calculateHeaders(
                request.headers as Record<string, string | string[] | undefined>,
                aiProvider.config.defaultHeaders,
            )
            const response = await fetch(url, {
                method: request.method,
                headers: cleanHeaders,
                body: JSON.stringify(request.body),
            })

            const responseContentType = response.headers.get('content-type')

            const data = await parseResponseData(response, responseContentType)

            await usageService(request.log).increaseProjectAndPlatformUsage({ projectId, incrementBy: 1, usageType: BillingUsageType.AI_TOKENS })

            await reply.code(response.status).type(responseContentType ?? 'text/plain').send(data)
        }
        catch (error) {
            if (error instanceof Response) {
                const errorData = await error.json()
                await reply.code(error.status).send(errorData)
            }
            else {
                exceptionHandler.handle(error, request.log)
                await reply
                    .code(500)
                    .send({ message: 'An unexpected error occurred in the proxy' })
            }
        }
    })
}

async function parseResponseData(response: Response, responseContentType: string | null) {
    if (responseContentType?.includes('application/json')) {
        return response.json()
    }
    if (responseContentType?.includes('application/octet-stream')) {
        return Buffer.from(await response.arrayBuffer())
    }
    if (responseContentType?.includes('audio/') || responseContentType?.includes('video/') || responseContentType?.includes('image/')) {
        return Buffer.from(await response.arrayBuffer())
    }
    return response.text()
}

function makeOpenAiResponse(
    message: string,
    code: string,
    params: Record<string, unknown>,
) {
    return {
        error: {
            message,
            type: 'invalid_request_error',
            param: params,
            code,
        },
    }
}

function buildUrl(baseUrl: string, path: string): string {
    const url = new URL(path, baseUrl)
    if (!['http:', 'https:'].includes(url.protocol)) {
        throw new Error('Invalid protocol. Only HTTP and HTTPS are allowed.')
    }
    return url.toString()
}

/**
 * Validates the target URL for SSRF protection
 * Blocks requests to private IPs and optionally validates against allowlist
 */
async function validateUrlForSSRF(url: string): Promise<void> {
    const parsedUrl = new URL(url)
    const hostname = parsedUrl.hostname
    
    // Check if hostname is a private IP
    if (await isPrivateIP(hostname)) {
        throw new Error(`SSRF protection: Requests to private/internal networks are not allowed`)
    }
    
    // Optional: Enable strict allowlist mode for production
    // Uncomment the following to enforce strict allowlisting:
    // if (!ALLOWED_AI_PROVIDER_DOMAINS.some(domain => hostname.endsWith(domain))) {
    //     throw new Error(`SSRF protection: Domain ${hostname} is not in the allowed AI providers list`)
    // }
}

const calculateHeaders = (
    requestHeaders: Record<string, string | string[] | undefined>,
    aiProviderDefaultHeaders: Record<string, string>,
): [string, string][] => {
    const forbiddenHeaders = [
        'authorization',
        'host',
        'content-length',
        'transfer-encoding',
        'connection',
        'keep-alive',
        'upgrade',
        'expect',
        'user-agent',
    ]
    const cleanedHeaders = Object.entries(requestHeaders).reduce(
        (acc, [key, value]) => {
            if (
                value !== undefined &&
                !forbiddenHeaders.includes(key.toLowerCase()) &&
                !key.toLowerCase().startsWith('x-')
            ) {
                acc[key as keyof typeof acc] = value
            }
            return acc
        },
        {} as Record<string, string | string[]>,
    )

    return Object.entries({
        ...cleanedHeaders,
        ...aiProviderDefaultHeaders,
    })
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => [
            key,
            Array.isArray(value) ? value.join(',') : value!.toString(),
        ])
}

const ProxyRequest = {
    config: {
        allowedPrincipals: [PrincipalType.ENGINE],
    },
    schema: {
        description: 'Proxy a request to a third party service',
        params: Type.Object({
            provider: Type.String(),
            '*': Type.String(),
        }),
    },
}
