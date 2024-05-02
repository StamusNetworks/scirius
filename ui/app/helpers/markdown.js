import DOMPurify from 'dompurify';
import { marked } from 'marked';

export function getMarkdownText(text) {
  if (typeof text === 'undefined' || text === null) return { __html: '' };
  const rawMarkup = DOMPurify.sanitize(marked.parse(text));
  return { __html: rawMarkup };
}
