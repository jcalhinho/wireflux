import { escapeHtml } from "./helpers.js";
import { t } from "./i18n.js";

function sanitizeUrl(url) {
  const value = String(url || "").trim();
  if (/^https?:\/\//i.test(value)) {
    return value;
  }
  return "";
}

function renderInlineMarkdown(input) {
  const raw = String(input || "");
  const linkTokens = [];
  const codeTokens = [];

  let text = raw.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, href) => {
    const safeHref = sanitizeUrl(href);
    if (!safeHref) {
      return label;
    }
    const tokenIndex = linkTokens.push({ label, href: safeHref }) - 1;
    return `@@LINK_${tokenIndex}@@`;
  });

  text = text.replace(/`([^`\n]+)`/g, (_, code) => {
    const tokenIndex = codeTokens.push(code) - 1;
    return `@@CODE_${tokenIndex}@@`;
  });

  let html = escapeHtml(text);
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  html = html.replace(/~~([^~]+)~~/g, "<del>$1</del>");

  html = html.replace(/@@CODE_(\d+)@@/g, (_, idx) => {
    const code = codeTokens[Number(idx)] ?? "";
    return `<code>${escapeHtml(code)}</code>`;
  });

  html = html.replace(/@@LINK_(\d+)@@/g, (_, idx) => {
    const link = linkTokens[Number(idx)];
    if (!link) {
      return "";
    }
    return `<a href="${escapeHtml(link.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link.label)}</a>`;
  });

  return html;
}

function createCodeBlock(lines, lang = "") {
  const language = lang ? `<span class="code-lang">${escapeHtml(lang)}</span>` : "";
  return `<pre class="ai-code"><div class="code-head">${language}</div><code>${escapeHtml(lines.join("\n"))}</code></pre>`;
}

export function renderMarkdownToHtml(markdownText, options = {}) {
  const loading = Boolean(options.loading);
  const lines = String(markdownText || "")
    .replace(/\r\n?/g, "\n")
    .split("\n");

  if (lines.length === 0 || (lines.length === 1 && !lines[0].trim())) {
    return loading
      ? `<p>${escapeHtml(t("markdown.streaming"))}</p><p class="ai-stream-cursor">▌</p>`
      : `<p>${escapeHtml(t("markdown.no.data"))}</p>`;
  }

  const html = [];
  let inUl = false;
  let inOl = false;
  let inCode = false;
  let codeLang = "";
  let codeLines = [];

  const closeLists = () => {
    if (inUl) {
      html.push("</ul>");
      inUl = false;
    }
    if (inOl) {
      html.push("</ol>");
      inOl = false;
    }
  };

  const flushCode = () => {
    html.push(createCodeBlock(codeLines, codeLang));
    inCode = false;
    codeLang = "";
    codeLines = [];
  };

  for (const line of lines) {
    const trimmed = line.trim();

    if (inCode) {
      if (trimmed.startsWith("```")) {
        flushCode();
      } else {
        codeLines.push(line);
      }
      continue;
    }

    if (trimmed.startsWith("```")) {
      closeLists();
      inCode = true;
      codeLang = trimmed.slice(3).trim();
      codeLines = [];
      continue;
    }

    if (!trimmed) {
      closeLists();
      continue;
    }

    const heading = /^(#{1,4})\s+(.+)$/.exec(trimmed);
    if (heading) {
      closeLists();
      const level = heading[1].length;
      html.push(`<h${level}>${renderInlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }

    if (/^---+$/.test(trimmed)) {
      closeLists();
      html.push("<hr/>");
      continue;
    }

    const blockquote = /^>\s?(.+)$/.exec(trimmed);
    if (blockquote) {
      closeLists();
      html.push(`<blockquote>${renderInlineMarkdown(blockquote[1])}</blockquote>`);
      continue;
    }

    const orderedItem = /^\d+\.\s+(.+)$/.exec(trimmed);
    if (orderedItem) {
      if (inUl) {
        html.push("</ul>");
        inUl = false;
      }
      if (!inOl) {
        html.push("<ol>");
        inOl = true;
      }
      html.push(`<li>${renderInlineMarkdown(orderedItem[1])}</li>`);
      continue;
    }

    const unorderedItem = /^[-*•]\s+(.+)$/.exec(trimmed);
    if (unorderedItem) {
      if (inOl) {
        html.push("</ol>");
        inOl = false;
      }
      if (!inUl) {
        html.push("<ul>");
        inUl = true;
      }
      html.push(`<li>${renderInlineMarkdown(unorderedItem[1])}</li>`);
      continue;
    }

    closeLists();
    html.push(`<p>${renderInlineMarkdown(trimmed)}</p>`);
  }

  closeLists();
  if (inCode) {
    flushCode();
  }
  if (loading) {
    html.push('<p class="ai-stream-cursor">▌</p>');
  }

  return html.join("");
}
