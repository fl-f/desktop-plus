import { app, net } from 'electron'
import * as path from 'path'
import { getArchitecture } from '../lib/get-architecture'
import { getFileHash } from '../lib/get-file-hash'
import { getMainGUID } from '../lib/get-main-guid'

let hasSentFatalError = false

/** Cached bundle hashes, computed on first error report. */
let cachedBundleHashes: { main: string; renderer: string } | null = null

/**
 * Compute SHA-256 hashes of the installed main.js and renderer.js bundles.
 *
 * Results are cached for the lifetime of the process since bundle files don't
 * change while the app is running.
 */
async function getBundleHashes(): Promise<{
  main: string
  renderer: string
} | null> {
  if (cachedBundleHashes !== null) {
    return cachedBundleHashes
  }

  try {
    const appPath = app.getAppPath()
    const [main, renderer] = await Promise.all([
      getFileHash(path.join(appPath, 'main.js'), 'sha256'),
      getFileHash(path.join(appPath, 'renderer.js'), 'sha256'),
    ])
    cachedBundleHashes = { main, renderer }
    return cachedBundleHashes
  } catch {
    return null
  }
}

/** Report the error to Central. */
export async function reportError(
  error: Error,
  extra?: { [key: string]: string },
  nonFatal?: boolean
) {
  if (__DEV__) {
    return
  }

  const url = nonFatal
    ? __NON_FATAL_ERROR_REPORTING_ENDPOINT__
    : __ERROR_REPORTING_ENDPOINT__
  if (url === undefined) {
    return
  }

  // We never want to send more than one fatal error (i.e. crash) per
  // application session. This guards against us ending up in a feedback loop
  // where the act of reporting a crash triggers another unhandled exception
  // which causes us to report a crash and so on and so forth.
  if (nonFatal !== true) {
    if (hasSentFatalError) {
      return
    }
    hasSentFatalError = true
  }

  const data = new Map<string, string>()

  data.set('name', error.name)
  data.set('message', error.message)

  if (error.stack) {
    data.set('stack', error.stack)
  }

  data.set('platform', process.platform)
  data.set('architecture', getArchitecture(app))
  data.set('sha', __SHA__)
  data.set('version', app.getVersion())
  data.set('guid', await getMainGUID())

  const bundleHashes = await getBundleHashes()
  if (bundleHashes !== null) {
    data.set('mainBundleHash', bundleHashes.main)
    data.set('rendererBundleHash', bundleHashes.renderer)
  }

  if (extra) {
    for (const key of Object.keys(extra)) {
      data.set(key, extra[key])
    }
  }

  const body = [...data.entries()]
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
    )
    .join('&')

  try {
    await new Promise<void>((resolve, reject) => {
      const request = net.request({ method: 'POST', url })

      request.setHeader('Content-Type', 'application/x-www-form-urlencoded')

      request.on('response', response => {
        if (response.statusCode === 200) {
          resolve()
        } else {
          reject(
            `Got ${response.statusCode} - ${response.statusMessage} from central`
          )
        }
      })

      request.on('error', reject)

      request.end(body)
    })
    log.info('Error report submitted')
  } catch (e) {
    log.error('Failed submitting error report', error)
  }
}
