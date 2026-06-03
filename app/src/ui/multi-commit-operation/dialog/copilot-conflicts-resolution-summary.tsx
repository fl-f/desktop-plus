import * as React from 'react'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

import { shell } from '../../../lib/app-shell'
import { assertNever } from '../../../lib/fatal-error'
import {
  ICopilotResolutionSummary,
  IConflictContextReference,
  IConflictSourceLink,
} from '../../../lib/copilot-conflict-resolution'
import { MultiCommitOperationKind } from '../../../models/multi-commit-operation'
import { CopyButton } from '../../copy-button'
import { LinkButton } from '../../lib/link-button'
import { Octicon } from '../../octicons'
import * as octicons from '../../octicons/octicons.generated'

interface ICopilotConflictsResolutionSummaryProps {
  readonly summary: ICopilotResolutionSummary
  readonly operationKind: MultiCommitOperationKind
}

/**
 * Builds the operation subheading sentence — e.g. "Merging Feature-A
 * into Feature-B" — using only words (no arrows). Anchored below the
 * main "Resolution summary" heading so the user can see what's being
 * resolved without the long phrase dominating the card.
 */
function getOperationPhrase(
  kind: MultiCommitOperationKind,
  ourLabel: string,
  theirLabel: string
): string {
  switch (kind) {
    case MultiCommitOperationKind.Merge:
      return `Merging ${theirLabel} into ${ourLabel}`
    case MultiCommitOperationKind.Rebase:
      return `Rebasing ${ourLabel} onto ${theirLabel}`
    case MultiCommitOperationKind.CherryPick:
      return `Cherry-picking from ${theirLabel} into ${ourLabel}`
    case MultiCommitOperationKind.Squash:
      return `Squashing into ${ourLabel}`
    case MultiCommitOperationKind.Reorder:
      return `Reordering ${ourLabel}`
    default:
      return assertNever(kind, `Unknown operation kind: ${kind}`)
  }
}

/**
 * Renders Copilot-authored markdown as a sanitized HTML fragment. The model
 * is instructed to never emit URLs (it uses `#1234` / `abc1234` ids only)
 * so we can safely sanitize without needing iframe isolation.
 */
function renderMarkdown(markdown: string): string {
  const parsed = marked.parse(markdown)
  return DOMPurify.sanitize(parsed, {
    USE_PROFILES: { html: true },
    // Strip anchors entirely — Desktop owns links in the references block.
    FORBID_TAGS: ['a', 'img', 'script', 'style', 'iframe'],
  })
}

/** A commit SHA paired with its URL, for inline prefix matching. */
interface ICommitLink {
  readonly sha: string
  readonly url: string
}

/** Matches an inline `#1234` pull-request id or a 7-40 char commit SHA. */
const inlineSourceToken = /#(\d+)|\b([0-9a-f]{7,40})\b/gi

/**
 * Resolve an abbreviated or full commit SHA to a URL, but only when it
 * unambiguously matches a single gathered commit. An ambiguous prefix is
 * left as plain text rather than risk linking to the wrong commit.
 */
function resolveCommitUrl(
  sha: string,
  commitLinks: ReadonlyArray<ICommitLink>
): string | null {
  const lower = sha.toLowerCase()
  const matches = commitLinks.filter(c => c.sha.startsWith(lower))
  return matches.length === 1 ? matches[0].url : null
}

/**
 * Replace the inline `#1234` / `abc1234` source ids in a single text node
 * with Desktop-owned anchors, resolved against the gathered context. Ids
 * we can't resolve are left untouched, so a hex word or unknown number
 * never becomes a dead link.
 */
function linkifyTextNode(
  node: Text,
  doc: Document,
  prUrlByNumber: ReadonlyMap<number, string>,
  commitLinks: ReadonlyArray<ICommitLink>
): void {
  const text = node.textContent
  if (text === null || text.length === 0) {
    return
  }

  inlineSourceToken.lastIndex = 0
  const fragment = doc.createDocumentFragment()
  let lastIndex = 0
  let replaced = false
  let match = inlineSourceToken.exec(text)

  while (match !== null) {
    const [token, prDigits, sha] = match
    const url =
      prDigits !== undefined
        ? prUrlByNumber.get(Number.parseInt(prDigits, 10)) ?? null
        : sha !== undefined
        ? resolveCommitUrl(sha, commitLinks)
        : null

    if (url !== null) {
      if (match.index > lastIndex) {
        fragment.appendChild(
          doc.createTextNode(text.slice(lastIndex, match.index))
        )
      }
      const anchor = doc.createElement('a')
      anchor.textContent = token
      anchor.setAttribute('href', url)
      anchor.setAttribute('class', 'copilot-conflicts-summary-inline-link')
      fragment.appendChild(anchor)
      lastIndex = match.index + token.length
      replaced = true
    }

    match = inlineSourceToken.exec(text)
  }

  if (!replaced) {
    return
  }

  if (lastIndex < text.length) {
    fragment.appendChild(doc.createTextNode(text.slice(lastIndex)))
  }
  node.parentNode?.replaceChild(fragment, node)
}

/**
 * Turn the plain source ids the model wrote (`#1234` / `abc1234`) into
 * real links, using only URLs we gathered ourselves. Runs on the already
 * sanitized HTML and skips text inside `code`/`pre` so code identifiers
 * are never mangled.
 */
function linkifySources(
  html: string,
  prUrlByNumber: ReadonlyMap<number, string>,
  commitLinks: ReadonlyArray<ICommitLink>
): string {
  if (prUrlByNumber.size === 0 && commitLinks.length === 0) {
    return html
  }

  const doc = new DOMParser().parseFromString(html, 'text/html')
  const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT)
  const textNodes: Array<Text> = []

  let current = walker.nextNode()
  while (current !== null) {
    if (
      current instanceof Text &&
      current.parentElement?.closest('code, pre') == null
    ) {
      textNodes.push(current)
    }
    current = walker.nextNode()
  }

  for (const node of textNodes) {
    linkifyTextNode(node, doc, prUrlByNumber, commitLinks)
  }

  return doc.body.innerHTML
}

/**
 * Build the lookup maps the inline linkifier needs from the flat source
 * link list, guarding against any non-https URL slipping into an anchor.
 */
function buildSourceLinkMaps(sourceLinks: ReadonlyArray<IConflictSourceLink>): {
  readonly prUrlByNumber: ReadonlyMap<number, string>
  readonly commitLinks: ReadonlyArray<ICommitLink>
} {
  const prUrlByNumber = new Map<number, string>()
  const commitLinks: Array<ICommitLink> = []

  for (const link of sourceLinks) {
    if (!link.url.startsWith('https://')) {
      continue
    }
    if (link.kind === 'pullRequest') {
      const prNumber = Number.parseInt(link.id, 10)
      if (Number.isFinite(prNumber)) {
        prUrlByNumber.set(prNumber, link.url)
      }
    } else {
      commitLinks.push({ sha: link.id.toLowerCase(), url: link.url })
    }
  }

  return { prUrlByNumber, commitLinks }
}

/**
 * The Copilot resolution summary card rendered at the top of the conflict
 * resolution dialog. Combines a deterministic title, the model-authored
 * markdown body, and a Desktop-rendered references block with real links
 * to PRs and commits.
 */
export class CopilotConflictsResolutionSummary extends React.Component<ICopilotConflictsResolutionSummaryProps> {
  private markdownRef: HTMLDivElement | null = null

  public render() {
    const { summary, operationKind } = this.props
    const phrase = getOperationPhrase(
      operationKind,
      summary.ourLabel,
      summary.theirLabel
    )

    return (
      <section
        className="copilot-conflicts-summary"
        aria-label="Resolution summary"
      >
        <header className="copilot-conflicts-summary-header">
          <h2 className="copilot-conflicts-summary-title">
            <Octicon
              symbol={octicons.copilot}
              className="copilot-conflicts-summary-copilot-icon"
            />
            <span>Resolution summary</span>
          </h2>
          <p className="copilot-conflicts-summary-operation">{phrase}</p>
        </header>
        {this.renderMarkdownBody()}
        {this.renderReferences()}
      </section>
    )
  }

  private renderMarkdownBody(): JSX.Element | null {
    const { markdown, sourceLinks } = this.props.summary
    if (markdown === null || markdown.trim() === '') {
      return null
    }

    const { prUrlByNumber, commitLinks } = buildSourceLinkMaps(sourceLinks)
    const html = linkifySources(
      renderMarkdown(markdown),
      prUrlByNumber,
      commitLinks
    )

    return (
      <div
        ref={this.onMarkdownRef}
        className="copilot-conflicts-summary-markdown"
        // Sanitized via DOMPurify, then linkified with Desktop-owned URLs.
        dangerouslySetInnerHTML={{ __html: html }}
      />
    )
  }

  private onMarkdownRef = (element: HTMLDivElement | null): void => {
    if (this.markdownRef === element) {
      return
    }
    if (this.markdownRef !== null) {
      this.markdownRef.removeEventListener('click', this.onMarkdownClick)
    }
    this.markdownRef = element
    if (element !== null) {
      element.addEventListener('click', this.onMarkdownClick)
    }
  }

  // Native listener (not a JSX handler) so the wrapper stays a plain,
  // non-interactive container — the real interactive elements are the
  // injected <a href> anchors, which are keyboard-focusable and activate
  // on Enter, dispatching the click this delegates from.
  private onMarkdownClick = (event: MouseEvent): void => {
    const { target } = event
    if (!(target instanceof Element)) {
      return
    }
    const anchor = target.closest('a.copilot-conflicts-summary-inline-link')
    if (anchor === null) {
      return
    }
    event.preventDefault()
    const href = anchor.getAttribute('href')
    if (href !== null && href.length > 0) {
      shell.openExternal(href)
    }
  }

  private renderReferences(): JSX.Element | null {
    const { references } = this.props.summary
    if (references.length === 0) {
      return null
    }

    return (
      <div className="copilot-conflicts-summary-references">
        <h3 className="copilot-conflicts-summary-references-title">Context</h3>
        <ul className="copilot-conflicts-summary-reference-list">
          {references.map((ref, i) => (
            <li
              key={referenceKey(ref, i)}
              className="copilot-conflicts-summary-reference-item"
            >
              {renderReference(ref)}
            </li>
          ))}
        </ul>
      </div>
    )
  }
}

function referenceKey(ref: IConflictContextReference, index: number): string {
  switch (ref.kind) {
    case 'pullRequest':
      return `pr-${ref.pullRequest.number}`
    case 'commit':
      return `commit-${ref.commit.sha}-${index}`
    default:
      return assertNever(ref, `Unknown reference kind: ${ref}`)
  }
}

/**
 * Render a reference title as a link when we have a URL, or as plain
 * text otherwise.
 */
function renderTitle(text: string, url: string | null): JSX.Element {
  if (url === null) {
    return (
      <span className="copilot-conflicts-summary-reference-title">{text}</span>
    )
  }
  return (
    <LinkButton uri={url} className="copilot-conflicts-summary-reference-title">
      {text}
    </LinkButton>
  )
}

function renderReference(ref: IConflictContextReference): JSX.Element {
  switch (ref.kind) {
    case 'pullRequest':
      return (
        <>
          <Octicon
            symbol={octicons.gitPullRequest}
            className="copilot-conflicts-summary-reference-icon"
          />
          {renderTitle(ref.pullRequest.title, ref.pullRequest.url)}
          <span className="copilot-conflicts-summary-reference-id">
            #{ref.pullRequest.number}
          </span>
        </>
      )

    case 'commit':
      return (
        <>
          <Octicon
            symbol={octicons.gitCommit}
            className="copilot-conflicts-summary-reference-icon"
          />
          {renderTitle(ref.commit.summary, ref.commit.url)}
          <span className="copilot-conflicts-summary-reference-commit-ref">
            <span className="ref selectable">{ref.commit.shortSha}</span>
            <CopyButton
              ariaLabel="Copy the full SHA"
              copyContent={ref.commit.sha}
            />
          </span>
          {!ref.commit.isOnRemote && (
            <span className="copilot-conflicts-summary-reference-tag">
              local only
            </span>
          )}
        </>
      )
    default:
      return assertNever(ref, `Unknown reference kind: ${ref}`)
  }
}
