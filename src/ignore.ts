/** Minimal glob: `**` matches across directories, `*` within one segment, everything else literal. Paths use `/`. */
export function globToRegExp(glob: string): RegExp {
  let g = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  g = g.replace(/\/\*\*$/, '\u0001').replace(/\*\*\//g, '\u0002').replace(/\*\*/g, '\u0003').replace(/\*/g, '[^/]*');
  g = g.replace(/\u0001/g, '(?:/.*)?').replace(/\u0002/g, '(?:.*/)?').replace(/\u0003/g, '.*');
  return new RegExp(`^${g}$`);
}
export function isIgnored(path: string, patterns: RegExp[]): boolean { return patterns.some((p) => p.test(path)); }
