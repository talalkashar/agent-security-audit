"use client";

import DOMPurify from "dompurify";

const BANNER = "<strong>Notes</strong>";

export function NoteView({ note }: { note: { body: string } }) {
  return (
    <div>
      <p dangerouslySetInnerHTML={{ __html: BANNER }} />
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(note.body) }} />
    </div>
  );
}
