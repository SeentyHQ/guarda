import { LineCounter, isMap, isSeq, isScalar, parseDocument, type Node } from 'yaml';
import type { ActionRef, Skipped } from '../types.js';

export function parseUses(value: string): { repo: string; ref: string; refKind: ActionRef['refKind'] } | { skip: string } {
  if (value.includes('${{')) return { skip: 'expression' };
  if (value.startsWith('./') || value.startsWith('../')) return { skip: 'local' };
  if (value.startsWith('docker://')) return { skip: 'docker' };
  const at = value.lastIndexOf('@');
  if (at === -1) return { skip: 'no ref' };
  const path = value.slice(0, at); const ref = value.slice(at + 1);
  const parts = path.split('/');
  if (parts.length < 2 || !parts[0] || !parts[1]) return { skip: 'malformed' };
  const repo = `${parts[0]}/${parts[1]}`;
  const refKind: ActionRef['refKind'] = /^[0-9a-f]{40}([0-9a-f]{24})?$/i.test(ref) ? 'sha' : ref.startsWith('refs/heads/') ? 'branch' : 'tag';
  return { repo, ref, refKind };
}

export function parseWorkflow(content: string, workflowPath: string): { actions: ActionRef[]; skipped: Skipped[] } {
  const lc = new LineCounter();
  const doc = parseDocument(content, { lineCounter: lc });
  if (doc.errors.length > 0) { const pos = doc.errors[0]!.linePos?.[0]; return { actions: [], skipped: [{ path: workflowPath, reason: 'parse-error', detail: pos ? `invalid syntax at line ${pos.line}, column ${pos.col}` : 'invalid syntax' }] }; }
  const actions: ActionRef[] = []; const skipped: Skipped[] = [];
  const visit = (node: Node | null | undefined): void => {
    if (isMap(node)) {
      for (const pair of node.items) {
        const key = isScalar(pair.key) ? String(pair.key.value) : '';
        if (key === 'uses' && isScalar(pair.value) && typeof pair.value.value === 'string') {
          const line = pair.value.range ? lc.linePos(pair.value.range[0]).line : 0;
          const parsed = parseUses(pair.value.value);
          if ('skip' in parsed) skipped.push({ path: workflowPath, reason: 'unsupported-entry', detail: `${pair.value.value}: ${parsed.skip}` });
          else actions.push({ ...parsed, workflow: workflowPath, line });
        } else visit(pair.value as Node);
      }
    } else if (isSeq(node)) for (const item of node.items) visit(item as Node);
  };
  visit(doc.contents);
  return { actions, skipped };
}
