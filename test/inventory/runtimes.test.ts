import { describe, expect, it } from 'vitest';
import { parseComposerRuntime, parseDockerfile, parseEngines, parseImageLines, parsePythonVersion, parseToolVersions, parseVersionFile } from '../../src/inventory/runtimes.js';

const slim = (r: { slug: string; version: string | null; precision: string; line?: number }) => `${r.slug}@${r.version ?? '?'}:${r.precision}${r.line ? '#' + r.line : ''}`;

describe('Dockerfile', () => {
  it('reads every stage, maps official images to catalog slugs, keeps the numeric part of the tag', () => {
    const r = parseDockerfile([
      '# syntax=docker/dockerfile:1',
      'ARG NODE=22',
      'FROM node:22.1.0-slim AS build',
      'FROM docker.io/library/php:8.2-fpm-alpine',
      'from NGINX:1.26.2',
      'FROM build AS test',
      'FROM scratch',
      'FROM ubuntu:22.04',
      'FROM python',
      'FROM ghcr.io/acme/tool:1.2.3',
      'FROM httpd@sha256:abcdef',
    ].join('\n'), 'Dockerfile');
    expect(r.runtimes.map(slim)).toEqual(['nodejs@22.1.0:exact#3', 'php@8.2:major#4', 'nginx@1.26.2:exact#5', 'ubuntu@22.04:major#8', 'python@?:unknown#9', 'apache-httpd@?:unknown#11']);
    expect(r.runtimes[0]).toMatchObject({ file: 'Dockerfile', raw: 'node:22.1.0-slim' });
    expect(r.skipped).toEqual([]); // a non-catalog image is still an image (see 'container images' below), not a skip
  });
});

describe('version files', () => {
  it('.nvmrc and .node-version: v prefix, majors and aliases', () => {
    expect(parseVersionFile('v22.1.0\n', '.nvmrc', 'nodejs').runtimes.map(slim)).toEqual(['nodejs@22.1.0:exact#1']);
    expect(parseVersionFile('22', '.node-version', 'nodejs').runtimes.map(slim)).toEqual(['nodejs@22:major#1']);
    expect(parseVersionFile('lts/*', '.nvmrc', 'nodejs').runtimes.map(slim)).toEqual(['nodejs@?:unknown#1']);
  });
  it('.python-version', () => {
    expect(parsePythonVersion('3.12.4\n', '.python-version').runtimes.map(slim)).toEqual(['python@3.12.4:exact#1']);
    expect(parsePythonVersion('pypy3.10-7.3.12', '.python-version').runtimes.map(slim)).toEqual(['python@?:unknown#1']);
  });
  it('.tool-versions: one tool per line, catalog tools only', () => {
    const r = parseToolVersions('nodejs 22.1.0\npython 3.12\nruby 3.3.0 # comment\nterraform 1.9.0\nphp 8.3.12\n', '.tool-versions');
    expect(r.runtimes.map(slim)).toEqual(['nodejs@22.1.0:exact#1', 'python@3.12:major#2', 'ruby@3.3.0:exact#3', 'php@8.3.12:exact#5']);
    expect(r.skipped).toEqual([]);
  });
});

describe('manifests', () => {
  it('package.json engines.node: exact, range or x-range', () => {
    expect(parseEngines('{"engines":{"node":"22.23.4"}}', 'package.json').runtimes.map(slim)).toEqual(['nodejs@22.23.4:exact']);
    expect(parseEngines('{"engines":{"node":">=22"}}', 'package.json').runtimes.map(slim)).toEqual(['nodejs@>=22:range']);
    expect(parseEngines('{"name":"x"}', 'package.json').runtimes).toEqual([]);
    expect(parseEngines('{', 'package.json').skipped[0]).toMatchObject({ path: 'package.json', reason: 'parse-error' });
  });
  it('composer.json require.php', () => {
    expect(parseComposerRuntime('{"require":{"php":"^8.2","laravel/framework":"^11"}}', 'composer.json').runtimes.map(slim)).toEqual(['php@^8.2:range']);
    expect(parseComposerRuntime('{"require":{"php":"8.2.33"}}', 'composer.json').runtimes.map(slim)).toEqual(['php@8.2.33:exact']);
    expect(parseComposerRuntime('{"require":{}}', 'composer.json').runtimes).toEqual([]);
  });
});

describe('container images', () => {
  it('a Dockerfile yields every image it pulls, first-party ones included, with tag or digest', () => {
    const r = parseDockerfile(['FROM node:22.1.0-slim AS build', 'FROM ghcr.io/acme/tool:1.2.3', 'FROM build', 'FROM litellm/litellm@sha256:abcdef', 'FROM scratch', 'FROM php'].join('\n'), 'Dockerfile');
    expect(r.images.map((i) => `${i.name}:${i.tag ?? ''}@${i.digest ?? ''}#${i.line}`)).toEqual(['library/node:22.1.0-slim@#1', 'ghcr.io/acme/tool:1.2.3@#2', 'litellm/litellm:@sha256:abcdef#4', 'library/php:@#6']);
  });
  it('compose files and Kubernetes manifests: every image: line', () => {
    const r = parseImageLines(['services:', '  api:', '    image: "litellm/litellm:1.107.0"', '  db:', '    image: postgres:16', '  web:', '    build: .'].join('\n'), 'docker-compose.yml');
    expect(r.images.map((i) => `${i.name}:${i.tag}#${i.line}`)).toEqual(['litellm/litellm:1.107.0#3', 'library/postgres:16#5']);
    const k = parseImageLines(['spec:', '  containers:', "    - image: 'ghcr.io/acme/api@sha256:0123'", '      name: api'].join('\n'), 'k8s/api.yaml');
    expect(k.images.map((i) => `${i.name}@${i.digest}`)).toEqual(['ghcr.io/acme/api@sha256:0123']);
  });
});
