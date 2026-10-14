#!/usr/bin/env python3
"""Run a GitHub Actions workflow on this machine at an exact commit, and write a receipt a later audit can check.

This is local CI, never a GitHub-hosted check. Hosted runners are blocked by account billing, so the receipt records
what a hosted run would have proved: which commit, which workflow bytes, which commands, which tool versions, which
exit codes. A receipt says "pass" only when every step was reproduced here and passed with the toolchain the workflow
asks for. Any failure says "fail". Anything this runner cannot reproduce makes it "incomplete", never "pass".

Standard library only, Python 3.9+. It runs the workflow's commands on this machine: read README.md in this folder,
and use --dry-run to see the plan first.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import hashlib
import io
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

SCHEMA = 'lighthouse-ci-receipt/v1'
LABEL = "Local CI on the owner's machine. Not a GitHub-hosted check."
RESULTS = ('pass', 'fail', 'incomplete')
JOB_RESULTS = ('success', 'failure', 'skipped', 'incomplete')
STEP_RESULTS = ('pass', 'fail', 'skip', 'unsupported', 'not-run')
LOCKFILES = {'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'uv.lock',
             'poetry.lock', 'Pipfile.lock', 'requirements.txt', 'Cargo.lock', 'go.sum', 'gradle-wrapper.properties',
             'libs.versions.toml'}
# Host variables a step may see. Everything else stays out, as it would on a fresh hosted runner.
PASS_ENV = {'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TZ',
            'TMPDIR', 'DISPLAY', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy',
            'no_proxy', 'all_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS', 'REQUESTS_CA_BUNDLE',
            'CURL_CA_BUNDLE', 'PIP_CERT', 'GIT_SSL_CAINFO', 'JAVA_HOME', 'JAVA_TOOL_OPTIONS', 'ANDROID_HOME',
            'ANDROID_SDK_ROOT', 'GRADLE_USER_HOME', 'PLAYWRIGHT_BROWSERS_PATH', 'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD',
            'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'COREPACK_HOME', 'PNPM_HOME', 'NVM_DIR'}
ARTIFACT_LIMIT = 200 * 1024 * 1024
DEFAULT_JOB_MINUTES = 360


class RunnerError(Exception):
    """The request itself is wrong: an unknown commit or workflow, a bad input."""


class Unsupported(Exception):
    """Something this runner cannot reproduce. The receipt names it and cannot pass."""


# ---------------------------------------------------------------------------------------------------------------------
# YAML: the subset workflows use. Anything outside it (anchors, aliases, tags, several documents, multi-line quoted
# values) is refused with a line number instead of being guessed.

class YamlError(ValueError):
    def __init__(self, message, line=None):
        super().__init__('line %d: %s' % (line, message) if line else message)


_ESCAPES = {'0': '\0', 'a': '\a', 'b': '\b', 't': '\t', '\t': '\t', 'n': '\n', 'v': '\v', 'f': '\f', 'r': '\r',
            'e': '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', 'N': '\x85', '_': '\xa0', 'L': '\u2028',
            'P': '\u2029'}


def _resolve(s):
    """YAML 1.2 core schema, as GitHub reads workflows: `on`, `yes` and `off` stay strings."""
    if s in ('', '~', 'null', 'Null', 'NULL'):
        return None
    if s in ('true', 'True', 'TRUE'):
        return True
    if s in ('false', 'False', 'FALSE'):
        return False
    if re.fullmatch(r'[-+]?[0-9]+', s):
        return int(s)
    if re.fullmatch(r'0o[0-7]+', s):
        return int(s[2:], 8)
    if re.fullmatch(r'0x[0-9a-fA-F]+', s):
        return int(s[2:], 16)
    if re.fullmatch(r'[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?', s):
        return float(s)
    if re.fullmatch(r'[-+]?\.(?:inf|Inf|INF)', s):
        return float('-inf') if s.startswith('-') else float('inf')
    if s in ('.nan', '.NaN', '.NAN'):
        return float('nan')
    return s


def _quoted(text, pos, line):
    """A single- or double-quoted scalar starting at text[pos]. Returns (value, index after the closing quote)."""
    quote, i, out = text[pos], pos + 1, []
    while i < len(text):
        c = text[i]
        if quote == "'":
            if c == "'":
                if text[i + 1:i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                return ''.join(out), i + 1
        else:
            if c == '"':
                return ''.join(out), i + 1
            if c == '\\':
                e = text[i + 1:i + 2]
                if e in _ESCAPES:
                    out.append(_ESCAPES[e])
                    i += 2
                    continue
                width = {'x': 2, 'u': 4, 'U': 8}.get(e)
                digits = text[i + 2:i + 2 + width] if width else ''
                if width and re.fullmatch(r'[0-9a-fA-F]{%d}' % width, digits):
                    out.append(chr(int(digits, 16)))
                    i += 2 + width
                    continue
                raise YamlError('invalid escape in a double-quoted value', line)
        out.append(c)
        i += 1
    raise YamlError('a quoted value must end on the line it starts', line)


def _cut_comment(text):
    m = re.search(r'[ \t]#', text)
    return (text[:m.start()] if m else text).rstrip()


class _NeedMore(Exception):
    pass


def _flow_space(s, pos):
    while pos < len(s):
        c = s[pos]
        if c in ' \t\n':
            pos += 1
        elif c == '#' and (pos == 0 or s[pos - 1] in ' \t\n'):
            nl = s.find('\n', pos)
            pos = len(s) if nl < 0 else nl
        else:
            break
    return pos


def _flow(s, pos, line):
    """A flow node ([...], {...} or a scalar) at s[pos]. Returns (value, index after it)."""
    pos = _flow_space(s, pos)
    if pos >= len(s):
        raise _NeedMore()
    c = s[pos]
    if c in '[{':
        close, out = (']', []) if c == '[' else ('}', {})
        pos += 1
        while True:
            pos = _flow_space(s, pos)
            if pos >= len(s):
                raise _NeedMore()
            if s[pos] == close:
                return out, pos + 1
            if c == '[':
                item, pos = _flow(s, pos, line)
                out.append(item)
            else:
                key, pos = _flow_scalar(s, pos, line)
                pos = _flow_space(s, pos)
                if pos >= len(s):
                    raise _NeedMore()
                value = None
                if s[pos] == ':':
                    pos = _flow_space(s, pos + 1)
                    if pos >= len(s):
                        raise _NeedMore()
                    if s[pos] not in ',}':
                        value, pos = _flow(s, pos, line)
                key = key if isinstance(key, str) else json.dumps(key)
                if key in out:
                    raise YamlError('duplicate key %r' % key, line)
                out[key] = value
            pos = _flow_space(s, pos)
            if pos >= len(s):
                raise _NeedMore()
            if s[pos] == ',':
                pos += 1
                continue
            if s[pos] == close:
                return out, pos + 1
            raise YamlError('expected "," or "%s"' % close, line)
    return _flow_scalar(s, pos, line)


def _flow_scalar(s, pos, line):
    c = s[pos]
    if c in '"\'':
        return _quoted(s, pos, line)
    if c in '&*!|>@`,]}':
        raise YamlError('unsupported or empty value in a flow collection', line)
    start = pos
    while pos < len(s):
        ch = s[pos]
        if ch in ',[]{}\n':
            break
        if ch == ':' and (pos + 1 == len(s) or s[pos + 1] in ' \t\n,[]{}'):
            break
        if ch == '#' and s[pos - 1] in ' \t':
            break
        pos += 1
    return _resolve(s[start:pos].strip()), pos


def _fold(lines):
    """Folded block scalar: single line breaks become spaces, except around more-indented lines."""
    lead = 0
    while lead < len(lines) and lines[lead] == '':
        lead += 1
    if lead == len(lines):
        return '\n' * lead
    text, i = '\n' * lead + lines[lead], lead + 1
    while i < len(lines):
        j = i
        while j < len(lines) and lines[j] == '':
            j += 1
        empties, prev, nxt = j - i, lines[i - 1], lines[j]
        if prev.startswith((' ', '\t')) or nxt.startswith((' ', '\t')):
            text += '\n' + '\n' * empties
        else:
            text += '\n' * empties if empties else ' '
        text += nxt
        i = j + 1
    return text


class _Yaml:
    def __init__(self, text):
        if text.startswith('\ufeff'):
            text = text[1:]
        self.lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        self.i = 0

    def fail(self, message, j):
        raise YamlError(message, j + 1)

    def content(self):
        """Index of the next line that is not blank or a comment, from self.i."""
        j = self.i
        while j < len(self.lines):
            s = self.lines[j].strip()
            if s and not s.startswith('#'):
                return j
            j += 1
        return None

    def indent(self, j):
        line = self.lines[j]
        n = len(line) - len(line.lstrip(' '))
        if line[n:n + 1] == '\t':
            self.fail('tabs are not allowed in indentation', j)
        return n

    @staticmethod
    def item(text):
        return text == '-' or text.startswith('- ')

    def document(self):
        j = self.content()
        if j is not None and re.fullmatch(r'---(?:[ \t]+#.*)?', self.lines[j].rstrip()):
            self.i = j + 1
            j = self.content()
        if j is None:
            return None
        if self.lines[j].startswith('%'):
            self.fail('directives are not supported', j)
        value = self.block(self.indent(j))
        j = self.content()
        if j is not None:
            self.fail('unexpected content here (only one document is supported)', j)
        return value

    def block(self, ind):
        j = self.content()
        text = self.lines[j][ind:]
        if self.item(text):
            return self.sequence(ind)
        if self.key(text, j) is not None:
            return self.mapping(ind)
        return self.scalar(text, ind - 1, j)

    def key(self, text, j):
        """(name, rest after the colon) when the line is a `key: value` entry, else None."""
        if text[:1] in '"\'':
            name, end = _quoted(text, 0, j + 1)
            m = re.match(r'[ \t]*:(?=[ \t]|$)', text[end:])
            return (name, text[end + m.end():]) if m else None
        if text[:1] in '[{&*!|>%@`#' or text.startswith('? '):
            return None
        for idx, ch in enumerate(text):
            if ch == '#' and idx > 0 and text[idx - 1] in ' \t':
                return None
            if ch == ':' and (idx + 1 == len(text) or text[idx + 1] in ' \t'):
                name = text[:idx].rstrip()
                return (name, text[idx + 1:]) if name else None
        return None

    def mapping(self, ind):
        out = {}
        while True:
            j = self.content()
            if j is None or self.indent(j) < ind:
                return out
            if self.indent(j) > ind:
                self.fail('unexpected indentation', j)
            text = self.lines[j][ind:]
            if re.fullmatch(r'(?:---|\.\.\.)(?:[ \t].*)?', text):
                self.fail('only one document is supported', j)
            if self.item(text):
                self.fail('a list item cannot follow a key at the same indentation', j)
            kv = self.key(text, j)
            if kv is None:
                self.fail('expected "key: value"', j)
            name, rest = kv
            if name in out:
                self.fail('duplicate key %r' % name, j)
            self.i = j + 1
            rest = rest.strip()
            out[name] = self.below(ind) if not rest or rest.startswith('#') else self.scalar(rest, ind, j)

    def sequence(self, ind):
        items = []
        while True:
            j = self.content()
            if j is None or self.indent(j) < ind:
                return items
            if self.indent(j) > ind:
                self.fail('unexpected indentation', j)
            text = self.lines[j][ind:]
            if not self.item(text):
                return items
            rest = text[1:].lstrip(' ')
            col = ind + len(text) - len(rest)
            if not rest or rest.startswith('#'):
                self.i = j + 1
                items.append(self.below(ind, same_indent_list=False))
            elif self.item(rest) or self.key(rest, j) is not None:
                # "- key: value": the entry continues on the following lines at the column after the dash.
                self.lines[j] = ' ' * col + rest
                self.i = j
                items.append(self.block(col))
            else:
                items.append(self.scalar(rest, ind, j))

    def below(self, ind, same_indent_list=True):
        """A value on the lines after its key: nested deeper, or a list at the key's own indentation."""
        j = self.content()
        if j is None:
            return None
        k = self.indent(j)
        if k > ind:
            return self.block(k)
        if k == ind and same_indent_list and self.item(self.lines[j][k:]):
            return self.sequence(k)
        return None

    def scalar(self, text, parent, j):
        """A value starting on line j. Continuation lines must be indented more than `parent`."""
        self.i = j + 1
        head = text[0]
        if head in '&*!@`':
            self.fail('anchors, aliases, tags and reserved indicators are not supported', j)
        if head in '|>':
            return self.block_scalar(text, parent, j)
        if head in '[{':
            buf = text
            while True:
                try:
                    value, end = _flow(buf, 0, j + 1)
                    break
                except _NeedMore:
                    k = self.content()
                    if k is None or self.indent(k) <= parent:
                        self.fail('a flow collection is not closed', j)
                    buf += '\n' + self.lines[k].strip()
                    self.i = k + 1
            rest = buf[end:].strip()
            if rest and not rest.startswith('#'):
                self.fail('unexpected text after a flow collection', j)
            return value
        if head in '"\'':
            value, end = _quoted(text, 0, j + 1)
            rest = text[end:]
            if rest.strip() and not re.match(r'[ \t]+#', rest):
                self.fail('unexpected text after a quoted value', j)
            return value
        value = _cut_comment(text)
        parts = [value]
        while True:
            k = self.content()
            if k is None or self.indent(k) <= parent:
                break
            between = self.lines[self.i:k]
            if any(line.strip().startswith('#') for line in between):
                break
            parts.append('\n' * len(between) if between else ' ')
            parts.append(_cut_comment(self.lines[k].strip()))
            self.i = k + 1
        value = ''.join(parts)
        if re.search(r':(?:[ \t]|$)', value):
            self.fail('a plain value cannot contain ": "; quote it', j)
        return _resolve(value) if len(parts) == 1 else value

    def block_scalar(self, header, parent, j):
        m = re.fullmatch(r'([|>])(?:([+-])([1-9])?|([1-9])([+-])?)?(?:[ \t]+#.*)?[ \t]*', header)
        if not m:
            self.fail('invalid block scalar header %r' % header, j)
        style, chomp = m.group(1), m.group(2) or m.group(5) or ''
        digit = m.group(3) or m.group(4)
        k = j + 1
        if digit:
            width = parent + int(digit)
        else:
            width, scan = None, k
            while scan < len(self.lines):
                if self.lines[scan].strip():
                    width = len(self.lines[scan]) - len(self.lines[scan].lstrip(' '))
                    break
                scan += 1
            if width is None or width <= parent:
                width = parent + 1
        body = []
        while k < len(self.lines):
            line = self.lines[k]
            if not line.strip():
                body.append(line[width:])
                k += 1
                continue
            if len(line) - len(line.lstrip(' ')) < width:
                break
            body.append(line[width:])
            k += 1
        self.i = k
        if k == len(self.lines) and body and self.lines[-1] == '':
            body.pop()  # the empty string after a final newline is not a line
        end = len(body)
        while end and not body[end - 1].strip():
            end -= 1
        content, trailing = body[:end], len(body) - end
        if not content:
            return '\n' * trailing if chomp == '+' else ''
        text = '\n'.join(content) if style == '|' else _fold(content)
        if chomp == '-':
            return text
        if chomp == '+':
            return text + '\n' + '\n' * trailing
        return text + '\n'


def parse_yaml(text):
    """Parse a workflow file. Raises YamlError for anything outside the supported subset."""
    return _Yaml(text).document()


# ---------------------------------------------------------------------------------------------------------------------
# Expressions: ${{ }} with GitHub's operators, coercions and built-in functions.

class ExprError(ValueError):
    pass


_EXPR_TOKEN = re.compile(r"""
  (?P<ws>\s+)
| (?P<str>'(?:[^']|'')*')
| (?P<num>0x[0-9a-fA-F]+|-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?)
| (?P<op>==|!=|<=|>=|&&|\|\||[<>!()\[\].,*])
| (?P<id>[A-Za-z_][A-Za-z0-9_-]*)
""", re.X)
_STATUS_CALL = re.compile(r'\b(?:success|failure|always|cancelled)\s*\(', re.I)
_TEMPLATE = re.compile(r'\$\{\{(.*?)\}\}', re.S)
_UNAVAILABLE = re.compile(r'\b(secrets|vars)\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[)|\bgithub\s*\.\s*token\b', re.I)


class _Filtered(list):
    """The result of `.*`: a following property applies to every element."""


def _kind(v):
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'bool'
    if isinstance(v, (int, float)):
        return 'num'
    if isinstance(v, str):
        return 'str'
    return 'obj'


def _num(v):
    k = _kind(v)
    if k == 'null':
        return 0
    if k == 'bool':
        return 1 if v else 0
    if k == 'num':
        return v
    if k == 'str':
        s = v.strip()
        if not s:
            return 0
        try:
            return int(s, 16) if s.lower().startswith('0x') else float(s)
        except ValueError:
            return float('nan')
    return float('nan')


def _truthy(v):
    k = _kind(v)
    if k in ('null', 'bool'):
        return bool(v)
    if k == 'num':
        return v == v and v != 0
    if k == 'str':
        return v != ''
    return True


def _str(v):
    k = _kind(v)
    if k == 'null':
        return ''
    if k == 'bool':
        return 'true' if v else 'false'
    if k == 'num':
        if v != v:
            return 'NaN'
        if v in (float('inf'), float('-inf')):
            return 'Infinity' if v > 0 else '-Infinity'
        return str(int(v)) if float(v).is_integer() else repr(float(v))
    if k == 'str':
        return v
    return 'Array' if isinstance(v, list) else 'Object'


def _equal(a, b):
    ka, kb = _kind(a), _kind(b)
    if ka == kb:
        if ka == 'str':
            return a.lower() == b.lower()
        if ka == 'obj':
            return a is b
        return a == b
    if 'obj' in (ka, kb):
        return False
    return _num(a) == _num(b)


def _compare(op, a, b):
    if op == '==':
        return _equal(a, b)
    if op == '!=':
        return not _equal(a, b)
    ka, kb = _kind(a), _kind(b)
    if ka == kb == 'str':
        x, y = a.lower(), b.lower()
    else:
        if 'obj' in (ka, kb):
            return False
        x, y = _num(a), _num(b)
        if x != x or y != y:
            return False
    return {'<': x < y, '<=': x <= y, '>': x > y, '>=': x >= y}[op]


def _member(obj, name):
    if isinstance(obj, _Filtered):
        return _Filtered(v for v in (_member(x, name) for x in obj) if v is not None)
    if isinstance(obj, dict):
        if name in obj:
            return obj[name]
        low = name.lower()
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() == low:
                return v
    return None


class _ExprParser:
    def __init__(self, src):
        self.src, self.toks, self.p, pos = src, [], 0, 0
        while pos < len(src):
            m = _EXPR_TOKEN.match(src, pos)
            if not m:
                raise ExprError('cannot read %r in %r' % (src[pos:pos + 12], src))
            pos = m.end()
            if m.lastgroup != 'ws':
                self.toks.append((m.lastgroup, m.group()))

    def peek(self):
        return self.toks[self.p] if self.p < len(self.toks) else ('end', '')

    def at(self, *ops):
        k, v = self.peek()
        return k == 'op' and v in ops

    def take(self):
        t = self.peek()
        if t[0] == 'end':
            raise ExprError('the expression ends early: %r' % self.src)
        self.p += 1
        return t

    def expect(self, op):
        if not self.at(op):
            raise ExprError('expected %r in %r' % (op, self.src))
        self.p += 1

    def parse(self):
        node = self.or_()
        if self.p != len(self.toks):
            raise ExprError('unexpected %r in %r' % (self.peek()[1], self.src))
        return node

    def or_(self):
        node = self.and_()
        while self.at('||'):
            self.p += 1
            node = ('or', node, self.and_())
        return node

    def and_(self):
        node = self.eq()
        while self.at('&&'):
            self.p += 1
            node = ('and', node, self.eq())
        return node

    def eq(self):
        node = self.cmp()
        while self.at('==', '!='):
            node = ('cmp', self.take()[1], node, self.cmp())
        return node

    def cmp(self):
        node = self.unary()
        while self.at('<', '<=', '>', '>='):
            node = ('cmp', self.take()[1], node, self.unary())
        return node

    def unary(self):
        if self.at('!'):
            self.p += 1
            return ('not', self.unary())
        return self.postfix()

    def postfix(self):
        node = self.primary()
        while True:
            if self.at('.'):
                self.p += 1
                k, v = self.take()
                if k == 'op' and v == '*':
                    node = ('star', node)
                elif k == 'id':
                    node = ('prop', node, v)
                else:
                    raise ExprError('expected a property name in %r' % self.src)
            elif self.at('['):
                self.p += 1
                index = self.or_()
                self.expect(']')
                node = ('index', node, index)
            else:
                return node

    def primary(self):
        k, v = self.take()
        if k == 'num':
            if v.lower().startswith('0x'):
                return ('lit', int(v, 16))
            return ('lit', float(v) if re.search(r'[.eE]', v) else int(v))
        if k == 'str':
            return ('lit', v[1:-1].replace("''", "'"))
        if k == 'id':
            if v in ('true', 'false'):
                return ('lit', v == 'true')
            if v == 'null':
                return ('lit', None)
            if self.at('('):
                self.p += 1
                args = []
                if not self.at(')'):
                    args.append(self.or_())
                    while self.at(','):
                        self.p += 1
                        args.append(self.or_())
                self.expect(')')
                return ('call', v.lower(), args)
            return ('ctx', v.lower())
        if k == 'op' and v == '(':
            node = self.or_()
            self.expect(')')
            return node
        raise ExprError('unexpected %r in %r' % (v, self.src))


class Expr:
    """Evaluates expressions against the contexts of one job or step."""

    def __init__(self, contexts, status='success', workspace=None, unavailable=None):
        self.contexts, self.status, self.workspace = contexts, status, workspace
        self.unavailable = unavailable if unavailable is not None else set()

    def evaluate(self, src):
        for m in _UNAVAILABLE.finditer(src):
            if m.group(0).lower().startswith('github'):
                self.unavailable.add('github.token')
            else:
                self.unavailable.add('%s.%s' % (m.group(1).lower(), m.group(2) or '*'))
        return self._eval(_ExprParser(src).parse())

    def _eval(self, n):
        t = n[0]
        if t == 'lit':
            return n[1]
        if t == 'ctx':
            return self.contexts.get(n[1])
        if t == 'prop':
            return _member(self._eval(n[1]), n[2])
        if t == 'index':
            obj, key = self._eval(n[1]), self._eval(n[2])
            if isinstance(obj, list):
                i = _num(key)
                ok = i == i and float(i).is_integer() and 0 <= int(i) < len(obj)
                return obj[int(i)] if ok else None
            return _member(obj, _str(key))
        if t == 'star':
            obj = self._eval(n[1])
            return _Filtered(obj.values() if isinstance(obj, dict) else obj if isinstance(obj, list) else [])
        if t == 'not':
            return not _truthy(self._eval(n[1]))
        if t == 'and':
            left = self._eval(n[1])
            return self._eval(n[2]) if _truthy(left) else left
        if t == 'or':
            left = self._eval(n[1])
            return left if _truthy(left) else self._eval(n[2])
        if t == 'cmp':
            return _compare(n[1], self._eval(n[2]), self._eval(n[3]))
        return self._call(n[1], n[2])

    def _call(self, name, args):
        if name in ('success', 'failure', 'always', 'cancelled'):
            if args:
                raise ExprError('%s() takes no arguments' % name)
            return {'success': self.status == 'success', 'failure': self.status == 'failure', 'always': True,
                    'cancelled': False}[name]
        vals = [self._eval(a) for a in args]
        if name == 'contains' and len(vals) == 2:
            if isinstance(vals[0], list):
                return any(_equal(x, vals[1]) for x in vals[0])
            return _str(vals[1]).lower() in _str(vals[0]).lower()
        if name == 'startswith' and len(vals) == 2:
            return _str(vals[0]).lower().startswith(_str(vals[1]).lower())
        if name == 'endswith' and len(vals) == 2:
            return _str(vals[0]).lower().endswith(_str(vals[1]).lower())
        if name == 'format' and vals:
            def rep(m):
                if m.group(0) in ('{{', '}}'):
                    return m.group(0)[0]
                i = int(m.group(1))
                if i >= len(vals) - 1:
                    raise ExprError('format() has no argument {%d}' % i)
                return _str(vals[i + 1])
            return re.sub(r'\{\{|\}\}|\{(\d+)\}', rep, _str(vals[0]))
        if name == 'join' and len(vals) in (1, 2):
            sep = _str(vals[1]) if len(vals) == 2 else ','
            return sep.join(_str(x) for x in vals[0]) if isinstance(vals[0], list) else _str(vals[0])
        if name == 'tojson' and len(vals) == 1:
            return json.dumps(vals[0], indent=2)
        if name == 'fromjson' and len(vals) == 1:
            try:
                return json.loads(_str(vals[0]))
            except ValueError:
                raise ExprError('fromJSON() could not read its input') from None
        if name == 'hashfiles' and vals:
            return self._hash_files([_str(v) for v in vals])
        raise ExprError('%s() with %d arguments is not supported' % (name, len(vals)))

    def _hash_files(self, patterns):
        if self.workspace is None:
            raise ExprError('hashFiles() needs a workspace')
        root, chosen = os.path.realpath(self.workspace), set()
        for pattern in patterns:
            negate = pattern.startswith('!')
            found = {os.path.realpath(f) for f in glob.glob(os.path.join(root, pattern[1:] if negate else pattern),
                                                             recursive=True) if os.path.isfile(f)}
            found = {f for f in found if f.startswith(root + os.sep)}
            chosen = chosen - found if negate else chosen | found
        if not chosen:
            return ''
        h = hashlib.sha256()
        for f in sorted(chosen):
            with open(f, 'rb') as fh:
                h.update(hashlib.sha256(fh.read()).digest())
        return h.hexdigest()


def interpolate(value, ev):
    """Substitutes ${{ }} in a string. A value that is exactly one expression keeps the expression's type."""
    if not isinstance(value, str) or '${{' not in value:
        return value
    whole = _TEMPLATE.fullmatch(value.strip())
    if whole and '${{' not in whole.group(1):
        return ev.evaluate(whole.group(1))
    return _TEMPLATE.sub(lambda m: _str(ev.evaluate(m.group(1))), value)


def condition(value, ev):
    """An `if:` value. Without a status function GitHub reads it as `success() && (value)`."""
    if value is None:
        src = 'success()'
    elif isinstance(value, (bool, int, float)):
        src = 'true' if _truthy(value) else 'false'
    else:
        src = str(value).strip()
        whole = _TEMPLATE.fullmatch(src)
        if whole and '${{' not in whole.group(1):
            src = whole.group(1)
    if not _STATUS_CALL.search(src):
        src = 'success() && (%s)' % src
    return _truthy(ev.evaluate(src))


# ---------------------------------------------------------------------------------------------------------------------
# Triggers, filters and matrices.

def _as_list(v):
    if v is None:
        return []
    return [_str(x) for x in v] if isinstance(v, list) else [_str(v)]


def _filter_regex(pattern):
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == '*':
            if pattern.startswith('**', i):
                i += 2
                if pattern.startswith('/', i):
                    out.append('(?:.*/)?')
                    i += 1
                else:
                    out.append('.*')
                continue
            out.append('[^/]*')
        elif c in '?+' and out:
            out.append(c)  # GitHub: zero or one, or one or more, of the preceding character
        elif c == '[' and pattern.find(']', i + 1) > 0:
            j = pattern.find(']', i + 1)
            out.append(pattern[i:j + 1])
            i = j + 1
            continue
        elif c == '\\' and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        else:
            out.append(re.escape(c))
        i += 1
    try:
        return re.compile(''.join(out))
    except re.error:
        raise RunnerError('cannot read the filter pattern %r' % pattern) from None


def filter_match(name, patterns):
    """GitHub filter semantics: later patterns win, and a leading ! excludes."""
    hit = False
    for p in patterns:
        negate = p.startswith('!')
        if _filter_regex(p[1:] if negate else p).fullmatch(name):
            hit = not negate
    return hit


def trigger(on, event, ref, base_branch, changed):
    """(runs, note). runs is False when GitHub would not start the workflow for this event."""
    if isinstance(on, str):
        events = {on: None}
    elif isinstance(on, list):
        events = {_str(e): None for e in on}
    elif isinstance(on, dict):
        events = on
    else:
        return False, 'the workflow has no triggers'
    if event not in events:
        return False, 'it does not run on %s (it runs on %s)' % (event, ', '.join(map(str, events)))
    cfg = events[event] if isinstance(events[event], dict) else {}
    notes = []
    if event in ('push', 'pull_request'):
        if event == 'pull_request':
            branch = base_branch
        else:
            branch = ref[len('refs/heads/'):] if ref.startswith('refs/heads/') else None
        if 'branches' in cfg or 'branches-ignore' in cfg:
            if branch is None:
                notes.append('branch filters not checked: no branch is known')
            elif 'branches' in cfg and not filter_match(branch, _as_list(cfg['branches'])):
                return False, 'branch %s is outside its branches filter' % branch
            elif 'branches-ignore' in cfg and filter_match(branch, _as_list(cfg['branches-ignore'])):
                return False, 'branch %s is in its branches-ignore filter' % branch
        elif event == 'push' and ('tags' in cfg or 'tags-ignore' in cfg):
            return False, 'its push trigger is for tags only'
        if 'paths' in cfg or 'paths-ignore' in cfg:
            if changed is None:
                notes.append('path filters not checked (no --base)')
            elif 'paths' in cfg:
                patterns = _as_list(cfg['paths'])
                if not any(filter_match(f, patterns) for f in changed):
                    return False, 'no changed file matches its paths filter'
            elif all(filter_match(f, _as_list(cfg['paths-ignore'])) for f in changed):
                return False, 'every changed file is in its paths-ignore filter'
    return True, '; '.join(['runs on %s' % event] + notes)


def expand_matrix(strategy):
    """Matrix combinations with include and exclude, in GitHub's order."""
    matrix = (strategy or {}).get('matrix') if isinstance(strategy, dict) else None
    if matrix is None:
        return [{}]
    if not isinstance(matrix, dict):
        raise Unsupported('a matrix built from an expression')
    base = {k: v for k, v in matrix.items() if k not in ('include', 'exclude')}
    for k, v in base.items():
        if not isinstance(v, list):
            raise Unsupported('matrix values for %r come from an expression' % k)
    combos = [{}] if base else []
    for k, values in base.items():
        combos = [dict(c, **{k: v}) for c in combos for v in values]
    for ex in matrix.get('exclude') or []:
        combos = [c for c in combos if not all(k in c and _equal(c[k], v) for k, v in ex.items())]
    for inc in matrix.get('include') or []:
        added = False
        for c in combos:
            if all(k not in base or _equal(c.get(k), v) for k, v in inc.items()):
                c.update(inc)
                added = True
        if not added:
            combos.append(dict(inc))
    return combos or [{}]


def job_order(jobs):
    order, state = [], {}

    def visit(name, path):
        if state.get(name) == 'done':
            return
        if state.get(name) == 'visiting':
            raise RunnerError('jobs need each other in a cycle: %s' % ' -> '.join(path + [name]))
        state[name] = 'visiting'
        for need in _as_list((jobs[name] or {}).get('needs')):
            if need not in jobs:
                raise RunnerError('job %s needs %s, which is not in the workflow' % (name, need))
            visit(need, path + [name])
        state[name] = 'done'
        order.append(name)

    for name in jobs:
        visit(name, [])
    return order


# ---------------------------------------------------------------------------------------------------------------------
# Results. verify recomputes these, so a receipt cannot claim more than its steps show.

def job_result_from_steps(steps):
    if any(s['result'] in ('unsupported', 'not-run') for s in steps):
        return 'incomplete'
    if any(s['result'] == 'fail' and not s.get('continue_on_error') for s in steps):
        return 'failure'
    return 'success'


def overall_result(record):
    jobs = [j for w in record['workflows'] for j in w['jobs']]
    steps = [s for j in jobs for s in j['steps']]
    if any(j['result'] == 'failure' and not j.get('continue_on_error') for j in jobs):
        return 'fail'
    if any(j['result'] == 'incomplete' for j in jobs):
        return 'incomplete'
    if any(d.get('material') for d in record['differences']) or record['unavailable']:
        return 'incomplete'
    if not any(s['result'] == 'pass' and s['kind'] == 'run' for s in steps):
        return 'incomplete'  # nothing was checked
    return 'pass'


# ---------------------------------------------------------------------------------------------------------------------
# The runner.

def _git(repo, *args, binary=False, check=True):
    p = subprocess.run(['git', '-C', repo] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       stdin=subprocess.DEVNULL)
    if check and p.returncode:
        raise RunnerError('git %s: %s' % (' '.join(args), p.stderr.decode('utf-8', 'replace').strip()))
    return p.stdout if binary else p.stdout.decode('utf-8', 'replace').strip()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _tool_version(cmd, cwd=None):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=cwd,
                           timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode:
        return None
    lines = [l.strip() for l in p.stdout.decode('utf-8', 'replace').splitlines()
             if l.strip() and not l.startswith('Picked up ')]
    return lines[0] if lines else None


def version_matches(spec, have):
    """True or False for specs like 22, 22.16, 22.16.0, 22.x or v22; None when the spec cannot be checked here."""
    m = re.fullmatch(r'v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?', _str(spec).strip())
    if not m or not have:
        return None
    want = [p for p in m.groups() if p is not None and p not in ('x', '*')]
    return re.findall(r'\d+', have)[:len(want)] == want


def _read_command_file(path):
    """GITHUB_OUTPUT and GITHUB_ENV: name=value lines and name<<DELIMITER blocks."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.read().replace('\r\n', '\n').split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        heredoc = line.find('<<')
        equals = line.find('=')
        if heredoc > 0 and (equals < 0 or heredoc < equals):
            name, delim, value = line[:heredoc], line[heredoc + 2:], []
            while i < len(lines) and lines[i] != delim:
                value.append(lines[i])
                i += 1
            if i >= len(lines):
                raise RunnerError('%s has an unterminated %s<<%s block' % (os.path.basename(path), name, delim))
            i += 1
            out[name] = '\n'.join(value)
        elif equals > 0:
            out[line[:equals]] = line[equals + 1:]
        else:
            raise RunnerError('%s has a line without "=": %r' % (os.path.basename(path), line[:60]))
    return out


def _shell_command(shell):
    if shell is None:
        return (['bash', '-e', '{0}'] if shutil.which('bash') else ['sh', '-e', '{0}']), '.sh'
    s = _str(shell).strip()
    if s == 'bash':
        return ['bash', '--noprofile', '--norc', '-eo', 'pipefail', '{0}'], '.sh'
    if s == 'sh':
        return ['sh', '-e', '{0}'], '.sh'
    if s == 'python':
        return ['python', '{0}'], '.py'
    if '{0}' in s and s.split()[0] not in ('pwsh', 'powershell', 'cmd'):
        return shlex.split(s), ''
    raise Unsupported('the %s shell' % s)


def _follow(path, stop):
    out = getattr(sys.stdout, 'buffer', None)
    if out is None:
        return
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if chunk:
                out.write(chunk)
                out.flush()
            elif stop.is_set():
                return
            else:
                time.sleep(0.2)


def _kill_group(pid):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.5)


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _os_release():
    try:
        with open('/etc/os-release', encoding='utf-8') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip().strip('"')
    except OSError:
        pass
    return None


class Runner:
    def __init__(self, repo, commit='HEAD', event='push', ref=None, base=None, base_branch='main', inputs=None,
                 accept_drift=False, out=None, keep=False, quiet=False, host_env=None, pass_env=(), tool_cache=None):
        if event not in ('push', 'pull_request', 'workflow_dispatch'):
            raise RunnerError('choose push, pull_request or workflow_dispatch')
        self.repo = _git(os.path.abspath(repo), 'rev-parse', '--show-toplevel')
        self.commit = self._commit(commit)
        self.tree = _git(self.repo, 'rev-parse', self.commit + '^{tree}')
        self.event, self.base_branch = event, base_branch
        self.ref = ref if ref is not None else self._branch_ref(commit)
        self.base = self._commit(base) if base else None
        self.inputs_given = dict(inputs or {})
        self.accept_drift, self.keep, self.quiet = accept_drift, keep, quiet
        self.tool_cache = os.path.abspath(tool_cache) if tool_cache else None
        self.name = self._repo_name()
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.out = os.path.abspath(out or os.path.join('ci-local-receipts', '%s-%s-%s' % (
            self.name.split('/')[-1], self.commit[:12], stamp)))
        host_env = dict(os.environ if host_env is None else host_env)
        allowed = PASS_ENV | set(pass_env)
        self.host_env = {k: v for k, v in host_env.items() if k in allowed}
        self.differences, self.unavailable, self.groups, self.tmp = [], set(), [], None

    def _commit(self, rev):
        sha = _git(self.repo, 'rev-parse', '--verify', '--quiet', rev + '^{commit}', check=False)
        if not re.fullmatch(r'[0-9a-f]{40}', sha):
            raise RunnerError('%s is not a commit in %s' % (rev, self.repo))
        return sha

    def _branch_ref(self, rev):
        full = _git(self.repo, 'rev-parse', '--symbolic-full-name', rev, check=False)
        if full.startswith('refs/heads/'):
            return full
        if full.startswith('refs/remotes/') and full.count('/') >= 3:
            return 'refs/heads/' + full.split('/', 3)[3]
        return ''

    def _repo_name(self):
        url = _git(self.repo, 'remote', 'get-url', 'origin', check=False)
        parts = [p for p in re.split(r'[/:]', re.sub(r'\.git/?$', '', url.rstrip('/'))) if p]
        if len(parts) >= 2 and '@' not in parts[-2] and '.' not in parts[-2]:
            return '%s/%s' % (parts[-2], parts[-1])
        return os.path.basename(self.repo)

    def workflow_paths(self):
        names = _git(self.repo, 'ls-tree', '--name-only', self.commit, '.github/workflows/', check=False)
        return [n for n in names.splitlines() if n.endswith(('.yml', '.yaml'))]

    def _load(self, path):
        raw = _git(self.repo, 'show', '%s:%s' % (self.commit, path), binary=True)
        try:
            data = parse_yaml(raw.decode('utf-8'))
        except (UnicodeDecodeError, YamlError) as e:
            raise RunnerError('%s: %s' % (path, e)) from None
        if not isinstance(data, dict) or not isinstance(data.get('jobs'), dict) or not data['jobs']:
            raise RunnerError('%s has no jobs' % path)
        return hashlib.sha256(raw).hexdigest(), data

    def _lockfiles(self):
        out = {}
        for path in _git(self.repo, 'ls-tree', '-r', '--name-only', self.commit).splitlines():
            if os.path.basename(path) in LOCKFILES and path.count('/') <= 2 and len(out) < 40:
                blob = _git(self.repo, 'cat-file', 'blob', '%s:%s' % (self.commit, path), binary=True)
                out[path] = hashlib.sha256(blob).hexdigest()
        return out

    def _host(self):
        tools = {}
        cwd = self.tmp or tempfile.gettempdir()
        for name, cmd in (('git', ['git', '--version']), ('bash', ['bash', '--version']),
                          ('node', ['node', '--version']),
                          ('npm', ['npm', '--version']), ('pnpm', ['pnpm', '--version']),
                          ('python3', ['python3', '--version']), ('java', ['java', '-version'])):
            v = _tool_version(cmd, cwd)
            if v:
                tools[name] = v
        return {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine(),
                'distro': _os_release(), 'tools': tools, 'env_passed': sorted(self.host_env)}

    def _inputs(self, data):
        on = data.get('on')
        spec = on.get('workflow_dispatch') if isinstance(on, dict) else None
        declared = (spec or {}).get('inputs') or {} if isinstance(spec, dict) else {}
        if self.event != 'workflow_dispatch':
            return {}
        unknown = sorted(set(self.inputs_given) - set(declared))
        if unknown:
            raise RunnerError('the workflow has no input named %s' % ', '.join(unknown))
        values = {}
        for name, d in declared.items():
            d = d or {}
            if name in self.inputs_given:
                value = self.inputs_given[name]
                if d.get('type') == 'choice' and value not in _as_list(d.get('options')):
                    raise RunnerError('input %s must be one of %s' % (name, ', '.join(_as_list(d.get('options')))))
                if d.get('type') == 'boolean':
                    value = value.lower() == 'true'
                elif d.get('type') == 'number':
                    value = _num(value)
            elif 'default' in d:
                value = d['default']
            elif d.get('required'):
                raise RunnerError('input %s is required: pass --input %s=VALUE' % (name, name))
            else:
                value = ''
            values[name] = value
        return values

    def _event_payload(self, inputs):
        ref_name = re.sub(r'^refs/(?:heads|tags)/', '', self.ref)
        if self.event == 'pull_request':
            pr = {'number': 0, 'draft': False, 'head': {'sha': self.commit, 'ref': ref_name},
                  'base': {'sha': self.base or '', 'ref': self.base_branch}}
            return {'action': 'synchronize', 'number': 0, 'pull_request': pr}
        if self.event == 'workflow_dispatch':
            return {'inputs': inputs, 'ref': self.ref}
        return {'ref': self.ref, 'after': self.commit, 'before': self.base or '0' * 40}

    def run(self, workflows, jobs=None, matrix_filter=None, ignore_filters=False, dry_run=False):
        changed = None
        if self.base:
            args = ['diff', '--name-only', '%s...%s' % (self.base, self.commit)] if self.event == 'pull_request' \
                else ['diff', '--name-only', self.base, self.commit]
            changed = [line for line in _git(self.repo, *args).splitlines() if line]
        record = {'schema': SCHEMA, 'label': LABEL, 'result': 'incomplete',
                  'repository': {'name': self.name, 'commit': self.commit, 'tree': self.tree},
                  'event': {'name': self.event, 'ref': self.ref, 'base': self.base,
                            'base_branch': self.base_branch if self.event == 'pull_request' else None,
                            'inputs': dict(self.inputs_given),
                            'changed_files': None if changed is None else len(changed)},
                  'runner': {}, 'started_at': _now(), 'finished_at': None, 'duration_ms': 0, 'workflows': [],
                  'lockfiles': {}, 'differences': self.differences, 'unavailable': []}
        if self.event == 'pull_request':
            self.differences.append({'kind': 'merge-commit', 'material': False, 'detail':
                                     'GitHub runs pull_request checks on a merge of head and base; this run used the '
                                     'head commit itself.'})
        started = time.monotonic()
        created = not os.path.exists(self.out)
        if not dry_run:
            if os.path.isdir(self.out) and os.listdir(self.out):
                raise RunnerError('%s already holds files; choose an empty --out folder' % self.out)
            os.makedirs(os.path.join(self.out, 'logs'), exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix='ci-local-')
        try:
            record['runner'] = {'tool': 'LighthouseRobotics/lighthouse tools/ci-local/ci_local.py',
                                'tool_sha256': _sha256_file(os.path.abspath(__file__)), 'host': self._host()}
            record['lockfiles'] = self._lockfiles()
            for path in workflows:
                self._workflow(record, path, changed, jobs, matrix_filter or {}, ignore_filters, dry_run)
        except KeyboardInterrupt:
            self.differences.append({'kind': 'interrupted', 'material': True, 'detail': 'The run was stopped early.'})
        except RunnerError:
            if not dry_run:
                shutil.rmtree(self.out, ignore_errors=True) if created else shutil.rmtree(
                    os.path.join(self.out, 'logs'), ignore_errors=True)
            raise
        finally:
            for pid in self.groups:
                _kill_group(pid)
            if not self.keep:
                shutil.rmtree(self.tmp, ignore_errors=True)
        record['unavailable'] = sorted(self.unavailable)
        record['finished_at'] = _now()
        record['duration_ms'] = int((time.monotonic() - started) * 1000)
        record['result'] = overall_result(record)
        return record

    def _say(self, text):
        if not self.quiet:
            print(text, flush=True)

    def _workflow(self, record, path, changed, wanted, matrix_filter, ignore_filters, dry_run):
        if '/' not in path:
            path = '.github/workflows/' + path
        digest, data = self._load(path)
        wrec = {'path': path, 'sha256': digest, 'name': _str(data.get('name')) or path, 'triggered': False,
                'trigger_note': '', 'jobs': []}
        record['workflows'].append(wrec)
        runs, note = trigger(data.get('on'), self.event, self.ref, self.base_branch, changed)
        wrec['trigger_note'] = note
        if not runs and not ignore_filters:
            self._say('== %s: not run, %s' % (path, note))
            return
        wrec['triggered'] = runs
        if not runs:
            wrec['trigger_note'] = 'run anyway with --ignore-filters: ' + note
        inputs = self._inputs(data)
        wrec['inputs'] = inputs
        jobs = data['jobs']
        order = job_order(jobs)
        if wanted:
            missing = [j for j in wanted if j not in jobs]
            if missing:
                raise RunnerError('%s has no job named %s' % (path, ', '.join(missing)))
            keep, todo = set(), list(wanted)
            while todo:
                j = todo.pop()
                if j not in keep:
                    keep.add(j)
                    todo.extend(_as_list((jobs[j] or {}).get('needs')))
            order = [j for j in order if j in keep]
        self._say('== %s (%s): %s' % (path, wrec['name'], wrec['trigger_note']))
        results = {}
        for job_id in order:
            job = jobs[job_id] or {}
            try:
                combos = expand_matrix(job.get('strategy'))
            except Unsupported as e:
                wrec['jobs'].append({'id': job_id, 'name': job_id, 'matrix': {}, 'runs_on': job.get('runs-on'),
                                     'result': 'incomplete', 'note': 'cannot reproduce %s' % e, 'steps': [],
                                     'outputs': {}})
                results[job_id] = {'result': 'incomplete', 'outputs': {}}
                continue
            for k, v in matrix_filter.items():
                combos = [c for c in combos if k in c and _str(c[k]) == v]
            if not combos:
                raise RunnerError('no %s matrix combination matches --matrix' % job_id)
            jrecs = [self._job(wrec, data, job_id, job, combo, i, len(combos), results, inputs, dry_run)
                     for i, combo in enumerate(combos)]
            got = [j['result'] for j in jrecs]
            if 'failure' in got:
                result = 'failure'
            elif 'incomplete' in got:
                result = 'incomplete'
            elif all(r == 'skipped' for r in got):
                result = 'skipped'
            else:
                result = 'success'
            outputs = {}
            for j in jrecs:
                outputs.update(j['outputs'])
            results[job_id] = {'result': result, 'outputs': outputs}

    def _contexts(self, data, inputs, job_id, ws, temp, combo, index, total, needs):
        ref_name = re.sub(r'^refs/(?:heads|tags)/', '', self.ref)
        pr = self.event == 'pull_request'
        github = {'event_name': self.event, 'event': self._event_payload(inputs), 'sha': self.commit,
                  'ref': self.ref, 'ref_name': ref_name, 'ref_type': 'branch', 'repository': self.name,
                  'repository_owner': self.name.split('/')[0] if '/' in self.name else '', 'workspace': ws,
                  'workflow': _str(data.get('name')), 'job': job_id, 'run_id': '0', 'run_number': '0',
                  'run_attempt': '1', 'actor': 'local', 'triggering_actor': 'local',
                  'server_url': 'https://github.com', 'api_url': 'https://api.github.com',
                  'base_ref': self.base_branch if pr else '', 'head_ref': ref_name if pr else '', 'token': ''}
        runner = {'os': 'Linux', 'arch': {'x86_64': 'X64', 'aarch64': 'ARM64', 'arm64': 'ARM64'}.get(
            platform.machine(), platform.machine()), 'name': 'ci-local', 'temp': temp, 'tool_cache': temp}
        strategy = {'fail-fast': True, 'job-index': index, 'job-total': total, 'max-parallel': 1}
        return {'github': github, 'env': {}, 'inputs': inputs, 'matrix': combo, 'strategy': strategy,
                'needs': needs, 'steps': {}, 'job': {'status': 'success'}, 'runner': runner, 'secrets': {},
                'vars': {}}

    def _job(self, wrec, data, job_id, job, combo, index, total, results, inputs, dry_run):
        jrec = {'id': job_id, 'name': job_id, 'matrix': combo, 'runs_on': job.get('runs-on'), 'result': 'incomplete',
                'note': '', 'steps': [], 'outputs': {}}
        wrec['jobs'].append(jrec)
        needs = {n: results[n] for n in _as_list(job.get('needs'))}
        jdir = tempfile.mkdtemp(dir=self.tmp, prefix='job-')
        ws, temp, tools = (os.path.join(jdir, d) for d in ('workspace', 'temp', 'tools'))
        for d in (ws, temp, tools):
            os.mkdir(d)
        ctx = self._contexts(data, inputs, job_id, ws, temp, combo, index, total, needs)
        ev = Expr(ctx, 'success', ws, self.unavailable)
        label = job_id + (' (%s)' % ', '.join('%s=%s' % (k, _str(v)) for k, v in combo.items()) if combo else '')
        if any(n['result'] == 'incomplete' for n in needs.values()):
            jrec['note'] = 'not run: it needs a job this runner could not reproduce'
            return jrec
        ev.status = 'success' if all(n['result'] == 'success' for n in needs.values()) else 'failure'
        try:
            if not condition(job.get('if'), ev):
                jrec.update(result='skipped', note='its if: condition was false')
                self._say('-- %s: skipped' % label)
                return jrec
            if job.get('name'):
                jrec['name'] = _str(interpolate(job['name'], ev))
        except ExprError as e:
            jrec['note'] = 'cannot evaluate: %s' % e
            return jrec
        labels = job.get('runs-on')
        labels = labels.get('labels') if isinstance(labels, dict) else labels
        text = ' '.join(_as_list(labels)).lower()
        problem = None
        if job.get('uses'):
            problem = 'a reusable workflow (%s)' % job['uses']
        elif job.get('container') or job.get('services'):
            problem = 'job containers and service containers'
        elif any(w in text for w in ('windows', 'macos', 'self-hosted')) or not text:
            problem = 'runs-on %s on this Linux host' % (text or 'nothing')
        elif not isinstance(job.get('steps'), list):
            problem = 'a job without steps'
        if problem:
            jrec['note'] = 'cannot reproduce %s' % problem
            self._say('-- %s: incomplete, %s' % (label, jrec['note']))
            return jrec
        self._say('-- %s on %s' % (label, text))
        if dry_run:
            return self._plan(jrec, job)
        try:
            return self._steps(jrec, data, job, ctx, ev, jdir, ws, temp, tools)
        finally:
            for pid in self.groups:
                _kill_group(pid)
            self.groups = []
            for s in jrec['steps']:
                if s.get('log'):
                    s['log_sha256'] = _sha256_file(os.path.join(self.out, s['log']))
            if not self.keep:
                shutil.rmtree(jdir, ignore_errors=True)

    def _plan(self, jrec, job):
        for idx, step in enumerate(job['steps']):
            what = step.get('uses') or ('run: ' + _str(step.get('run')).strip().split('\n')[0])
            handled = 'uses' not in step or self._handler(_str(step['uses'])) is not None
            cond = ' if: %s' % step['if'] if 'if' in step else ''
            self._say('   %2d. %s%s%s' % (idx + 1, what, cond, '' if handled else '  [cannot reproduce]'))
        jrec['note'] = 'dry run: nothing was executed'
        return jrec

    def _handler(self, uses):
        if uses.startswith(('./', 'docker://')):
            return None
        name = '/'.join(uses.split('@')[0].lower().split('/')[:2])
        return {'actions/checkout': self._checkout, 'actions/setup-node': self._setup_node,
                'actions/setup-python': self._setup_python, 'actions/setup-java': self._setup_java,
                'pnpm/action-setup': self._setup_pnpm, 'actions/cache': self._cache,
                'actions/upload-artifact': self._upload}.get(name)

    def _steps(self, jrec, data, job, ctx, ev, jdir, ws, temp, tools):
        env = {}
        for scope in (data.get('env'), job.get('env')):
            for k, v in (scope or {}).items():
                ctx['env'] = dict(env)
                env[k] = _str(interpolate(v, ev))
        ctx['env'] = dict(env)
        defaults = {}
        for scope in (data.get('defaults'), job.get('defaults')):
            defaults.update(((scope or {}).get('run') or {}) if isinstance(scope, dict) else {})
        path_prefix = [os.path.join(tools, 'bin')]
        minutes = _num(interpolate(job.get('timeout-minutes', DEFAULT_JOB_MINUTES), ev))
        deadline = time.monotonic() + 60 * (minutes if minutes == minutes and minutes > 0 else DEFAULT_JOB_MINUTES)
        status, stopped = 'success', None
        self.job_env = env
        for idx, step in enumerate(job['steps']):
            step = step or {}
            srec = {'index': idx, 'name': '', 'kind': 'action' if 'uses' in step else 'run', 'result': 'not-run',
                    'note': ''}
            if 'uses' in step:
                srec['uses'] = _str(step['uses'])
            jrec['steps'].append(srec)
            first = _str(step.get('run')).strip().split('\n')[0]
            srec['name'] = _str(step.get('name')) or ('Run ' + (srec.get('uses') or first))
            sid = _str(step.get('id')) or None
            if stopped:
                srec['note'] = stopped
                continue
            ev.status = ctx['job']['status'] = status
            ctx['env'] = dict(self.job_env)
            try:
                if step.get('name'):
                    srec['name'] = _str(interpolate(step['name'], ev))
                if not condition(step.get('if'), ev):
                    srec.update(result='skip', note='its if: condition was false' if status == 'success'
                                else 'skipped after an earlier failure')
                    self._say('   [skip] %s' % srec['name'])
                    if sid:
                        ctx['steps'][sid] = {'outputs': {}, 'outcome': 'skipped', 'conclusion': 'skipped'}
                    continue
                step_env = dict(self.job_env)
                for k, v in (step.get('env') or {}).items():
                    ctx['env'] = dict(step_env)
                    step_env[k] = _str(interpolate(v, ev))
                ctx['env'] = step_env
                started = time.monotonic()
                if 'uses' in step:
                    handler = self._handler(srec['uses'])
                    if handler is None:
                        raise Unsupported('the action %s' % srec['uses'])
                    with_ = {k: interpolate(v, ev) for k, v in (step.get('with') or {}).items()}
                    result, note, outputs = handler(with_, ws, jdir, path_prefix, step_env, srec)
                    srec['duration_ms'] = int((time.monotonic() - started) * 1000)
                elif 'run' in step:
                    result, note, outputs = self._run(step, srec, ev, defaults, ws, temp, path_prefix, step_env,
                                                      deadline, jrec)
                else:
                    raise Unsupported('a step with neither run nor uses')
            except Unsupported as e:
                srec.update(result='unsupported', note='cannot reproduce %s' % e)
                stopped = 'not run: an earlier step could not be reproduced'
                self._say('   [----] %s: %s' % (srec['name'], srec['note']))
                continue
            except ExprError as e:
                srec.update(result='unsupported', note='cannot evaluate: %s' % e)
                stopped = 'not run: an earlier step could not be reproduced'
                self._say('   [----] %s: %s' % (srec['name'], srec['note']))
                continue
            srec.update(result=result, note=note)
            outcome = 'success' if result == 'pass' else 'failure'
            conclusion = outcome
            if result == 'fail':
                coe = _truthy(interpolate(step.get('continue-on-error', False), ev))
                srec['continue_on_error'] = coe
                if coe:
                    conclusion = 'success'
                else:
                    status = 'failure'
            if sid:
                ctx['steps'][sid] = {'outputs': outputs, 'outcome': outcome, 'conclusion': conclusion}
            secs = srec.get('duration_ms', 0) / 1000
            self._say('   [%s] %s  %.1fs%s' % (result, srec['name'], secs, '  (%s)' % note if note else ''))
        ev.status = status
        ctx['env'] = dict(self.job_env)
        try:
            for k, v in (job.get('outputs') or {}).items():
                jrec['outputs'][k] = _str(interpolate(v, ev))
        except ExprError as e:
            jrec['note'] = 'cannot evaluate its outputs: %s' % e
        jrec['result'] = job_result_from_steps(jrec['steps'])
        if jrec['result'] == 'failure' and _truthy(interpolate(job.get('continue-on-error', False), ev)):
            jrec['continue_on_error'] = True
        return jrec

    def _run(self, step, srec, ev, defaults, ws, temp, path_prefix, env, deadline, jrec):
        script = _str(interpolate(step['run'], ev))
        shell = step.get('shell', defaults.get('shell'))
        cmd, suffix = _shell_command(interpolate(shell, ev) if shell is not None else None)
        wd = _str(interpolate(step.get('working-directory', defaults.get('working-directory')), ev))
        cwd = os.path.join(ws, wd) if wd else ws
        idx = srec['index']
        files = {name: os.path.join(temp, '%s-%d' % (name.lower(), idx)) for name in
                 ('GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_STEP_SUMMARY')}
        for f in files.values():
            open(f, 'w').close()
        proc_env = dict(self.host_env)
        proc_env.update(env)
        proc_env.update(self._defaults(ev.contexts, ws, temp, files))
        proc_env['PATH'] = os.pathsep.join(path_prefix + [proc_env.get('PATH', os.defpath)])
        limit = deadline - time.monotonic()
        if step.get('timeout-minutes') is not None:
            limit = min(limit, 60 * _num(interpolate(step['timeout-minutes'], ev)))
        log = 'logs/%s.%s.%d.log' % (re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.basename(
            ev.contexts['github']['workflow'] or 'workflow')), re.sub(r'[^A-Za-z0-9_.-]', '_', jrec['id'] + (
            '-%d' % ev.contexts['strategy']['job-index'] if ev.contexts['strategy']['job-total'] > 1 else '')), idx)
        srec.update(command=script, shell=' '.join(cmd), working_directory=wd, log=log)
        if not os.path.isdir(cwd):
            with open(os.path.join(self.out, log), 'w', encoding='utf-8') as f:
                f.write('working-directory %s does not exist\n' % wd)
            srec.update(exit_code=None, duration_ms=0)
            return 'fail', 'its working-directory does not exist', {}
        code, timed_out, ms = self._exec(script, cmd, suffix, cwd, proc_env, limit, os.path.join(self.out, log), temp)
        srec.update(exit_code=code, duration_ms=ms)
        try:
            outputs = _read_command_file(files['GITHUB_OUTPUT'])
            self.job_env.update(_read_command_file(files['GITHUB_ENV']))
        except RunnerError as e:
            return 'fail', str(e), {}
        with open(files['GITHUB_PATH'], encoding='utf-8', errors='replace') as f:
            for line in f.read().splitlines():
                if line.strip():
                    path_prefix.insert(0, line.strip())
        if timed_out:
            return 'fail', 'stopped at its timeout', outputs
        return ('pass' if code == 0 else 'fail'), '', outputs

    def _defaults(self, ctx, ws, temp, files):
        g = ctx['github']
        env = {'CI': 'true', 'GITHUB_ACTIONS': 'true', 'LIGHTHOUSE_CI_LOCAL': '1', 'GITHUB_WORKSPACE': ws,
               'GITHUB_SHA': self.commit, 'GITHUB_REF': self.ref, 'GITHUB_REF_NAME': g['ref_name'],
               'GITHUB_REF_TYPE': 'branch', 'GITHUB_EVENT_NAME': self.event, 'GITHUB_REPOSITORY': self.name,
               'GITHUB_REPOSITORY_OWNER': g['repository_owner'], 'GITHUB_JOB': g['job'],
               'GITHUB_WORKFLOW': g['workflow'], 'GITHUB_RUN_ID': '0', 'GITHUB_RUN_NUMBER': '0',
               'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_ACTOR': 'local', 'GITHUB_SERVER_URL': g['server_url'],
               'GITHUB_API_URL': g['api_url'], 'GITHUB_BASE_REF': g['base_ref'], 'GITHUB_HEAD_REF': g['head_ref'],
               'RUNNER_OS': 'Linux', 'RUNNER_ARCH': ctx['runner']['arch'], 'RUNNER_NAME': 'ci-local',
               'RUNNER_TEMP': temp, 'RUNNER_TOOL_CACHE': temp}
        event_path = os.path.join(temp, 'event.json')
        with open(event_path, 'w', encoding='utf-8') as f:
            json.dump(g['event'], f)
        env['GITHUB_EVENT_PATH'] = event_path
        env.update(files)
        return env

    def _exec(self, script, cmd, suffix, cwd, env, limit, logpath, temp):
        fd, path = tempfile.mkstemp(dir=temp, suffix=suffix)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(script)
        argv = [a.replace('{0}', path) for a in cmd]
        started = time.monotonic()
        with open(logpath, 'ab') as log:
            try:
                p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            except OSError as e:
                log.write(('could not start %s: %s\n' % (argv[0], e)).encode())
                return 127, False, 0
        self.groups.append(p.pid)
        stop, follower = threading.Event(), None
        if not self.quiet:
            follower = threading.Thread(target=_follow, args=(logpath, stop), daemon=True)
            follower.start()
        timed_out = False
        try:
            code = p.wait(timeout=max(limit, 0.001))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(p.pid)
            code = p.wait()
        except KeyboardInterrupt:
            _kill_group(p.pid)
            p.wait()
            raise
        finally:
            stop.set()
            if follower:
                follower.join(5)
        return code, timed_out, int((time.monotonic() - started) * 1000)

    # Known actions. Each returns (result, note, outputs) or raises Unsupported.

    def _drift(self, what, wanted, have):
        entry = {'kind': 'version', 'material': not self.accept_drift,
                 'detail': '%s %s wanted; %s used' % (what, _str(wanted), have)}
        if entry not in self.differences:
            self.differences.append(entry)
        return 'version drift: %s %s wanted, %s used' % (what, _str(wanted), have)

    def _checkout(self, with_, ws, jdir, path_prefix, env, srec):
        repo = _str(with_.get('repository'))
        if repo and repo.lower() != self.name.lower():
            raise Unsupported('a checkout of another repository (%s)' % repo)
        for flag in ('submodules', 'lfs'):
            if _truthy(with_.get(flag)) and _str(with_.get(flag)) != 'false':
                raise Unsupported('checkout with %s' % flag)
        target, ref = self.commit, _str(with_.get('ref'))
        if ref:
            target = None
            for candidate in (ref, 'origin/' + ref, 'refs/tags/' + ref):
                target = _git(self.repo, 'rev-parse', '--verify', '--quiet', candidate + '^{commit}', check=False)
                if target:
                    break
            if not target:
                raise Unsupported('a checkout of %s, which is not in the local repository (fetch it first)' % ref)
        dest = os.path.realpath(os.path.join(ws, _str(with_.get('path'))))
        if dest != os.path.realpath(ws) and not dest.startswith(os.path.realpath(ws) + os.sep):
            raise Unsupported('a checkout outside the workspace')
        if os.path.isdir(dest):
            for name in os.listdir(dest):
                full = os.path.join(dest, name)
                shutil.rmtree(full) if os.path.isdir(full) and not os.path.islink(full) else os.remove(full)
        _git(self.repo, 'clone', '--quiet', '--shared', '--no-checkout', self.repo, dest)
        _git(dest, 'checkout', '--quiet', '--detach', target)
        srec['checked_out'] = target
        depth = _str(with_.get('fetch-depth')) or '1'
        note = 'clean clone of %s' % target[:12]
        if depth != '0':
            note += '; full local history, where GitHub fetches depth %s' % depth
        return 'pass', note, {'ref': ref, 'commit': target}

    def _setup_node(self, with_, ws, jdir, path_prefix, env, srec):
        for k in ('registry-url', 'scope', 'always-auth'):
            if with_.get(k):
                raise Unsupported('setup-node %s' % k)
        want = with_.get('node-version')
        if want is None and with_.get('node-version-file'):
            want = self._version_file(ws, with_['node-version-file'])
        cached = cached_tool(self.tool_cache, 'node', want, 'node') if want is not None else None
        if cached:
            path_prefix.insert(0, cached)
        have = _tool_version([os.path.join(cached, 'node') if cached else 'node', '--version'], ws)
        srec['version'] = have
        if not have:
            raise Unsupported('Node.js, which is not installed here')
        if want is None:
            return 'pass', 'no version requested; Node.js %s' % have, {'node-version': have}
        ok = version_matches(want, have)
        note = 'Node.js %s matches %s' % (have, _str(want)) if ok else self._drift('Node.js', want, have)
        if cached:
            note += ', from the tool cache'
        if with_.get('cache') or _truthy(with_.get('package-manager-cache', False)):
            note += '; package cache not used'
        return 'pass', note, {'node-version': have}

    def _setup_python(self, with_, ws, jdir, path_prefix, env, srec):
        want = with_.get('python-version')
        if want is None and with_.get('python-version-file'):
            want = self._version_file(ws, with_['python-version-file'])
        m = re.fullmatch(r'(\d+)\.(\d+)(?:\.\d+)?', _str(want)) if want is not None else None
        cached = cached_tool(self.tool_cache, 'python', want, 'python3') if want is not None else None
        exe = (cached and os.path.join(cached, 'python3')) or (m and shutil.which('python%s.%s' % m.groups())) \
            or shutil.which('python3')
        if not exe:
            raise Unsupported('Python, which is not installed here')
        venv = os.path.join(jdir, 'python')
        p = subprocess.run([exe, '-m', 'venv', venv], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode:
            raise Unsupported('a fresh Python environment (%s -m venv failed)' % exe)
        path_prefix.insert(0, os.path.join(venv, 'bin'))
        have = _tool_version([os.path.join(venv, 'bin', 'python'), '--version']) or ''
        have = have.replace('Python ', '')
        srec['version'] = have
        note = 'fresh virtual environment from %s; installs stay in this run' % exe
        if want is not None:
            ok = version_matches(want, have)
            note = ('Python %s matches %s; ' % (have, _str(want)) if ok else
                    self._drift('Python', want, have) + '; ') + note
        if with_.get('cache'):
            note += '; package cache not used'
        return 'pass', note, {'python-version': have}

    def _setup_java(self, with_, ws, jdir, path_prefix, env, srec):
        want = with_.get('java-version')
        have = _tool_version(['java', '-version'], ws)
        srec['version'] = have
        if not have:
            raise Unsupported('Java, which is not installed here')
        number = (re.search(r'"([^"]+)"', have) or re.search(r'(\d[\w.+-]*)', have)).group(1)
        note = 'Java %s' % number
        if want is not None:
            note = 'Java %s matches %s' % (number, _str(want)) if version_matches(want, number) else \
                self._drift('Java', want, number)
        if with_.get('distribution'):
            note += '; %s requested, local JDK used (%s)' % (_str(with_['distribution']), have)
        return 'pass', note, {'version': number}

    def _setup_pnpm(self, with_, ws, jdir, path_prefix, env, srec):
        if with_.get('run_install') not in (None, False, 'false', ''):
            raise Unsupported('pnpm/action-setup run_install')
        want = _str(with_.get('version')) or None
        if want is None:
            try:
                with open(os.path.join(ws, _str(with_.get('package_json_file')) or 'package.json'),
                          encoding='utf-8') as f:
                    manager = _str(json.load(f).get('packageManager'))
            except (OSError, ValueError):
                manager = ''
            if not manager.startswith('pnpm@'):
                raise Unsupported('pnpm/action-setup without a version or a packageManager field')
            want = manager[len('pnpm@'):].split('+')[0]
        have = _tool_version(['pnpm', '--version'], ws if os.listdir(ws) else jdir)
        srec['version'] = have
        if not have:
            raise Unsupported('pnpm, which is not installed here')
        ok = version_matches(want, have)
        return 'pass', ('pnpm %s matches %s' % (have, want) if ok else self._drift('pnpm', want, have)), {}

    def _cache(self, with_, ws, jdir, path_prefix, env, srec):
        return 'pass', 'cache not used; it changes speed, not results', {'cache-hit': 'false'}

    def _upload(self, with_, ws, jdir, path_prefix, env, srec):
        name = re.sub(r'[^A-Za-z0-9_.-]', '_', _str(with_.get('name')) or 'artifact')
        root, files = os.path.realpath(jdir), set()
        for pattern in [p.strip() for p in _str(with_.get('path')).split('\n') if p.strip()]:
            negate = pattern.startswith('!')
            base = pattern[1:] if negate else pattern
            found = set()
            for hit in glob.glob(os.path.join(ws, base), recursive=True):
                if os.path.isdir(hit):
                    for root, _dirs, names in os.walk(hit):
                        found.update(os.path.join(root, n) for n in names)
                elif os.path.isfile(hit):
                    found.add(hit)
            files = files - found if negate else files | found
        outside = {f for f in files if not os.path.realpath(f).startswith(root + os.sep)}
        files -= outside
        if outside:
            srec['outside_job_folder'] = len(outside)
        if not files:
            missing = _str(with_.get('if-no-files-found')) or 'warn'
            if missing == 'error':
                return 'fail', 'no files to upload', {}
            return 'pass', 'nothing to upload', {}
        total = sum(os.path.getsize(f) for f in files)
        srec['artifact'] = {'name': name, 'files': len(files), 'bytes': total}
        if total > ARTIFACT_LIMIT:
            return 'pass', 'artifact %s not kept: %d bytes is over the local limit' % (name, total), {}
        dest = os.path.join(self.out, 'artifacts', name)
        for f in sorted(files):
            inside = f.startswith(ws + os.sep)
            rel = os.path.relpath(f, ws) if inside else os.path.join('_runner', os.path.relpath(f, jdir))
            os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
            shutil.copy2(f, os.path.join(dest, rel))
        srec['artifact']['kept'] = 'artifacts/%s' % name
        skipped = '; %d files outside the job folder not kept' % len(outside) if outside else ''
        return 'pass', 'kept %d files in artifacts/%s%s' % (len(files), name, skipped), {}

    @staticmethod
    def _version_file(ws, name):
        try:
            with open(os.path.join(ws, _str(name)), encoding='utf-8') as f:
                return f.read().strip().splitlines()[0].strip()
        except (OSError, IndexError):
            raise Unsupported('a version file %s that is not in the checkout' % _str(name)) from None


# ---------------------------------------------------------------------------------------------------------------------
# Tool cache: exact toolchain versions, laid out like a hosted runner's: <cache>/node/22.16.0/bin/node and
# <cache>/python/3.12.7/bin/python3.

def _version_key(name):
    return tuple(int(x) for x in re.findall(r'\d+', name)[:3])


def cached_tool(cache, tool, spec, exe):
    """The bin folder of the newest cached version that satisfies spec, or None."""
    if not cache:
        return None
    base = os.path.join(cache, tool)
    try:
        names = os.listdir(base)
    except OSError:
        return None
    fits = [n for n in names if version_matches(spec, n) and os.access(os.path.join(base, n, 'bin', exe), os.X_OK)]
    return os.path.join(base, max(fits, key=_version_key), 'bin') if fits else None


def safe_extract(tar, dest):
    """Extracts a tar archive, refusing absolute paths, `..`, devices and links that leave `dest`."""
    root = os.path.realpath(dest)
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(root, member.name))
        if os.path.isabs(member.name) or not (target == root or target.startswith(root + os.sep)):
            raise RunnerError('the archive has a path outside its folder: %s' % member.name)
        if not (member.isfile() or member.isdir() or member.issym()):
            raise RunnerError('the archive has a special file: %s' % member.name)
        if member.issym():
            link = os.path.realpath(os.path.join(os.path.dirname(target), member.linkname))
            if os.path.isabs(member.linkname) or not link.startswith(root + os.sep):
                raise RunnerError('the archive has a link outside its folder: %s' % member.name)
    checked = {'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}
    for member in tar.getmembers():
        tar.extract(member, root, **checked)


def fetch_node(version, cache, opener=urllib.request.urlopen):
    """Downloads an official Node.js build into the tool cache after checking it against nodejs.org's SHASUMS256."""
    version = version.lstrip('v')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise RunnerError('give an exact Node.js version such as 22.16.0')
    system = {'Linux': 'linux', 'Darwin': 'darwin'}.get(platform.system())
    arch = {'x86_64': 'x64', 'AMD64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if not system or not arch:
        raise RunnerError('no official Node.js build for %s %s' % (platform.system(), platform.machine()))
    dest = os.path.join(os.path.abspath(cache), 'node', version)
    if os.path.isfile(os.path.join(dest, 'bin', 'node')):
        return dest, 'already in the tool cache'
    name = 'node-v%s-%s-%s.tar.gz' % (version, system, arch)
    base = 'https://nodejs.org/dist/v%s/' % version
    with opener(base + 'SHASUMS256.txt', timeout=60) as r:
        sums = r.read().decode('utf-8')
    wanted = [line.split()[0] for line in sums.splitlines() if line.split()[-1:] == [name]]
    if len(wanted) != 1:
        raise RunnerError('SHASUMS256.txt for %s does not list %s' % (version, name))
    with opener(base + name, timeout=600) as r:
        data = r.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != wanted[0]:
        raise RunnerError('%s has SHA-256 %s, not the published %s' % (name, digest, wanted[0]))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    work = tempfile.mkdtemp(dir=os.path.dirname(dest), prefix='.fetch-')
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            safe_extract(tar, work)
        top = os.path.join(work, name[:-len('.tar.gz')])
        if not os.path.isfile(os.path.join(top, 'bin', 'node')):
            raise RunnerError('%s does not contain bin/node' % name)
        os.rename(top, dest)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return dest, 'SHA-256 %s matches nodejs.org SHASUMS256.txt' % digest


# ---------------------------------------------------------------------------------------------------------------------
# Verify a receipt.

def verify_receipt(path, repo=None):
    """Returns (problems, receipt). An empty list means the receipt is consistent and its logs are intact."""
    problems = []
    with open(path, encoding='utf-8') as f:
        r = json.load(f)
    need = lambda ok, message: ok or problems.append(message)
    need(isinstance(r, dict) and r.get('schema') == SCHEMA, 'schema is not %s' % SCHEMA)
    if problems:
        return problems, r
    need(r.get('label') == LABEL, 'the label must say this was local CI, not a hosted check')
    need(r.get('result') in RESULTS, 'result must be pass, fail or incomplete')
    repo_info = r.get('repository') or {}
    need(re.fullmatch(r'[0-9a-f]{40}', _str(repo_info.get('commit'))) is not None, 'repository.commit is not a SHA')
    workflows = r.get('workflows')
    need(isinstance(workflows, list), 'workflows must be a list')
    need(isinstance(r.get('differences'), list) and isinstance(r.get('unavailable'), list),
         'differences and unavailable must be lists')
    if problems:
        return problems, r
    base = os.path.dirname(os.path.abspath(path))
    for w in workflows:
        need(re.fullmatch(r'[0-9a-f]{64}', _str(w.get('sha256'))) is not None, '%s has no sha256' % w.get('path'))
        for j in w.get('jobs') or []:
            need(j.get('result') in JOB_RESULTS, 'job %s has an unknown result' % j.get('id'))
            steps = j.get('steps') or []
            for s in steps:
                need(s.get('result') in STEP_RESULTS and s.get('kind') in ('run', 'action'),
                     'a step of %s has an unknown result or kind' % j.get('id'))
                if s.get('log'):
                    full = os.path.normpath(os.path.join(base, s['log']))
                    if not full.startswith(base + os.sep) or not os.path.isfile(full):
                        problems.append('log %s is missing' % s['log'])
                    elif _sha256_file(full) != s.get('log_sha256'):
                        problems.append('log %s does not match its hash' % s['log'])
            if steps and j.get('result') in ('success', 'failure', 'incomplete'):
                need(job_result_from_steps(steps) == j['result'],
                     'job %s says %s but its steps say %s' % (j.get('id'), j['result'], job_result_from_steps(steps)))
    if not problems:
        expected = overall_result(r)
        need(expected == r['result'], 'the receipt says %s but its jobs and steps say %s' % (r['result'], expected))
    if repo:
        commit = repo_info['commit']
        if _git(repo, 'cat-file', '-t', commit, check=False) != 'commit':
            problems.append('commit %s is not in %s' % (commit[:12], repo))
        else:
            need(_git(repo, 'rev-parse', commit + '^{tree}') == repo_info.get('tree'), 'the tree does not match')
            for w in workflows:
                raw = _git(repo, 'show', '%s:%s' % (commit, w['path']), binary=True, check=False)
                need(hashlib.sha256(raw).hexdigest() == w['sha256'], '%s differs from the receipt' % w['path'])
            for p, digest in (r.get('lockfiles') or {}).items():
                raw = _git(repo, 'cat-file', 'blob', '%s:%s' % (commit, p), binary=True, check=False)
                need(hashlib.sha256(raw).hexdigest() == digest, 'lockfile %s differs from the receipt' % p)
    return problems, r


# ---------------------------------------------------------------------------------------------------------------------

def _pairs(values, flag):
    out = {}
    for v in values:
        if '=' not in v:
            raise RunnerError('%s takes NAME=VALUE, not %r' % (flag, v))
        k, val = v.split('=', 1)
        out[k] = val
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run', help='run workflows at a commit and write a receipt')
    run.add_argument('--repo', default='.', help='the repository (default: here)')
    run.add_argument('--commit', default='HEAD', help='any commit, branch or tag (default HEAD); uncommitted '
                                                      'changes are never included')
    run.add_argument('--workflow', action='append', default=[], help='a file in .github/workflows (repeatable)')
    run.add_argument('--all', action='store_true', help='every workflow, recording which ones the event triggers')
    run.add_argument('--job', action='append', default=[], help='only this job and the jobs it needs (repeatable)')
    run.add_argument('--matrix', action='append', default=[], help='NAME=VALUE: only matching combinations')
    run.add_argument('--event', default='push', choices=('push', 'pull_request', 'workflow_dispatch'))
    run.add_argument('--ref', help='e.g. refs/heads/main (default: the branch --commit names)')
    run.add_argument('--base', help='base commit: for pull_request contexts and for checking path filters')
    run.add_argument('--base-branch', default='main', help='pull_request base branch (default main)')
    run.add_argument('--input', action='append', default=[], help='workflow_dispatch input NAME=VALUE')
    run.add_argument('--accept-version-drift', action='store_true',
                     help='let a run with other tool versions than the workflow asks for pass; the receipt '
                          'still lists every difference')
    run.add_argument('--pass-env', action='append', default=[], help='also pass this host variable to steps')
    run.add_argument('--tool-cache', default=os.environ.get('CI_LOCAL_TOOL_CACHE'),
                     help='folder of exact toolchains: node/<version>/bin, python/<version>/bin '
                          '(default $CI_LOCAL_TOOL_CACHE)')
    run.add_argument('--ignore-filters', action='store_true', help='run workflows the event would not trigger')
    run.add_argument('--out', help='an empty folder for the receipt and logs')
    run.add_argument('--keep', action='store_true', help='keep the job workspaces')
    run.add_argument('--quiet', action='store_true', help='do not print step output')
    run.add_argument('--dry-run', action='store_true', help='print the plan; run nothing')
    fetch = sub.add_parser('fetch-node', help='download an official Node.js build into the tool cache')
    fetch.add_argument('version', help='an exact version such as 22.16.0')
    fetch.add_argument('--tool-cache', default=os.environ.get('CI_LOCAL_TOOL_CACHE'), required=not os.environ.get(
        'CI_LOCAL_TOOL_CACHE'))
    ver = sub.add_parser('verify', help='check a receipt and its logs, and optionally against the repository')
    ver.add_argument('receipt')
    ver.add_argument('--repo', help='the repository the receipt describes')
    args = ap.parse_args(argv)
    try:
        if args.command == 'fetch-node':
            dest, note = fetch_node(args.version, args.tool_cache)
            print('Node.js %s: %s (%s)' % (args.version, dest, note))
            return 0
        if args.command == 'verify':
            problems, r = verify_receipt(args.receipt, args.repo)
            for p in problems:
                print('problem: ' + p)
            if problems:
                return 1
            print('Receipt OK: %s for %s at %s (local CI, not a hosted check).' % (
                r['result'], r['repository'].get('name'), r['repository']['commit'][:12]))
            return 0
        def stop(_signum, _frame):
            raise KeyboardInterrupt()
        # A stopped runner still stops its steps' process groups and writes an "interrupted" receipt.
        signal.signal(signal.SIGTERM, stop)
        runner = Runner(args.repo, args.commit, args.event, args.ref, args.base, args.base_branch,
                        _pairs(args.input, '--input'), args.accept_version_drift, args.out, args.keep, args.quiet,
                        pass_env=args.pass_env, tool_cache=args.tool_cache)
        available = runner.workflow_paths()
        if args.workflow:
            chosen = [w if '/' in w else '.github/workflows/' + w for w in args.workflow]
            missing = [w for w in chosen if w not in available]
            if missing:
                raise RunnerError('not at %s: %s' % (runner.commit[:12], ', '.join(missing)))
        elif args.all or len(available) == 1:
            chosen = available
        else:
            raise RunnerError('choose --workflow or --all; this commit has %s' % (', '.join(available) or 'none'))
        record = runner.run(chosen, args.job, _pairs(args.matrix, '--matrix'), args.ignore_filters, args.dry_run)
        if args.dry_run:
            return 0
        path = os.path.join(runner.out, 'receipt.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=2)
            f.write('\n')
        for d in record['differences']:
            print('difference: %s%s' % (d['detail'], '' if d['material'] else ' (recorded; does not block a pass)'))
        for u in record['unavailable']:
            print('unavailable here: %s' % u)
        print('%s: %s at %s. Receipt: %s' % (record['result'].upper(), record['repository']['name'],
                                             record['repository']['commit'][:12], path))
        return {'pass': 0, 'fail': 1, 'incomplete': 2}[record['result']]
    except RunnerError as e:
        print('ci_local: %s' % e, file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
