import fs from 'fs/promises'
import { nanoid } from 'nanoid'
import path from 'path'
import simpleGit, { SimpleGit } from 'simple-git'
import { ConfigureRepoRequest, GitRepo } from 'workflow-axb-shared'
import { AppSystemProp } from 'workflow-server-shared'
import { AIxBlockError, ApEnvironment, ErrorCode } from 'workflow-shared'
import { userIdentityService } from '../../../authentication/user-identity/user-identity-service'
import { system } from '../../../helper/system/system'
import { userService } from '../../../user/user-service'

/**
 * Sanitizes a slug to prevent path traversal attacks.
 * Only allows alphanumeric characters, hyphens, and underscores.
 */
function sanitizeSlug(slug: string): string {
    // Remove any path traversal sequences and invalid characters
    const sanitized = slug
        .replace(/\.\./g, '') // Remove parent directory references
        .replace(/[/\\]/g, '') // Remove path separators
        .replace(/[^a-zA-Z0-9_-]/g, '_'); // Replace other invalid chars with underscore
    
    if (!sanitized || sanitized.length === 0) {
        throw new AIxBlockError({
            code: ErrorCode.VALIDATION_FAILED,
            params: { message: 'Invalid slug: slug cannot be empty or contain only invalid characters' },
        });
    }
    
    return sanitized;
}


export const gitHelper = {
    commitAndPush,
    createGitRepoAndReturnPaths,
    validateConnection,
}

async function commitAndPush(
    git: SimpleGit,
    gitRepo: GitRepo,
    commitMessage: string,
): Promise<void> {
    await git.add('.')
    await git.commit(commitMessage)
    await git.push('origin', gitRepo.branch)
}

async function createGitRepoAndReturnPaths(
    gitRepo: GitRepo,
    userId: string,
): Promise<{ flowFolderPath: string, git: SimpleGit, stateFolderPath: string, connectionsFolderPath: string }> {
    // Sanitize slug to prevent path traversal attacks
    const safeSlug = sanitizeSlug(gitRepo.slug)
    
    const tmpFolder = path.join('/', 'tmp', 'repo', gitRepo.projectId)
    try {
        await fs.rmdir(tmpFolder, { recursive: true })
    }
    catch (e) {
        // ignore
    }
    const flowFolderPath = path.join(
        tmpFolder,
        'projects',
        safeSlug,
        'flows',
    )
    const connectionsFolderPath = path.join(
        tmpFolder,
        'projects',
        safeSlug,
        'connections',
    )
    await fs.mkdir(flowFolderPath, { recursive: true })
    await fs.mkdir(connectionsFolderPath, { recursive: true })
    const stateFolderPath = path.join(
        tmpFolder,
        'projects',
        safeSlug,
        'state',
    )
    await fs.mkdir(stateFolderPath, { recursive: true })
    const keyPath = path.resolve(path.join('tmp', 'keys', gitRepo.id))
    await createOrGetSshKeyPath({ keyPath, sshPrivateKey: gitRepo.sshPrivateKey })
    const git = await initGitRepo(keyPath, gitRepo.remoteUrl, tmpFolder, gitRepo.branch)
    await git.pull('origin', gitRepo.branch)

    const user = await userService.getOneOrFail({
        id: userId,
    })
    const identity = await userIdentityService(system.globalLogger()).getBasicInformation(user.identityId)
    const { email, firstName, lastName } = identity
    await git.addConfig('user.email', email)
    await git.addConfig('user.name', `${firstName} ${lastName}`)
    return {
        git,
        flowFolderPath,
        stateFolderPath,
        connectionsFolderPath,
    }
}

async function createOrGetSshKeyPath({ keyPath, sshPrivateKey }: { keyPath: string, sshPrivateKey: string }): Promise<void> {
    await fs.mkdir(path.dirname(keyPath), { recursive: true })
    await fs.writeFile(keyPath, sshPrivateKey)
    await fs.chmod(keyPath, 0o600)
}

async function initGitRepo(
    keyPath: string,
    remoteUrl: string,
    baseDir: string,
    branch: string,
): Promise<SimpleGit> {
    const git = simpleGit({
        baseDir,
        binary: 'git',
    }).env('GIT_SSH_COMMAND', `ssh -i ${keyPath} -o StrictHostKeyChecking=no`)
    await git.init()
    await git.addRemote('origin', remoteUrl)
    await git.branch(['-M', branch])
    await git.pull('origin', branch)
    return git
}

async function validateConnection(request: ConfigureRepoRequest): Promise<void> {
    const environment = system.getOrThrow<ApEnvironment>(AppSystemProp.ENVIRONMENT)
    if (environment === ApEnvironment.TESTING) {
        return
    }
    const { remoteUrl, sshPrivateKey, branch } = request

    const tmpFolder = path.join('/', 'tmp', 'repo', nanoid(), 'validate')
    const keyPath = path.resolve(path.join('tmp', 'keys', nanoid()))

    try {
        await fs.mkdir(tmpFolder, { recursive: true })
        await createOrGetSshKeyPath({ keyPath, sshPrivateKey })
        await initGitRepo(keyPath, remoteUrl, tmpFolder, branch)
    }
    catch (error) {
        throw new AIxBlockError({
            code: ErrorCode.INVALID_GIT_CREDENTIALS,
            params: {
                message: (error as Error).message,
            },
        })
    }
    finally {
        await fs.rmdir(tmpFolder, { recursive: true })
        await fs.unlink(keyPath)
    }
}
