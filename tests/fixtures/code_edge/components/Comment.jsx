import DOMPurify from "isomorphic-dompurify";

// A name that contains "sanitized" is not a sanitizer call.
export function Comment({ unsanitizedHtml }) {
  return <div dangerouslySetInnerHTML={{ __html: unsanitizedHtml }} />;
}

// JSON.stringify does not escape </script>.
export function State({ user }) {
  return <script dangerouslySetInnerHTML={{ __html: `window.__U=${JSON.stringify(user)}` }} />;
}

export function LdJson({ data }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />;
}

// Safe: exact sanitizer calls, directly or through a variable, and JSON with "<" escaped.
export function Clean({ html, data }) {
  const clean = DOMPurify.sanitize(html);
  return (
    <>
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
      <div dangerouslySetInnerHTML={{ __html: clean }} />
      <script type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, "\\u003c") }} />
    </>
  );
}
