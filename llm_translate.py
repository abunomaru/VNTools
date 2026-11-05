#!/usr/bin/env python3
"""
Context-aware machine translation for visual novel scripts.

Instead of sending one line per request, lines are sent in chunks (default 30)
together with the speaker names and the lines just before the chunk, and the
model returns structured JSON keyed by line id. A glossary / style guide is
put in the cached system prompt.

Backends
  anthropic          official `anthropic` SDK (pip install anthropic)
  openai             OpenAI Chat Completions (stdlib urllib)
  openai-compatible  any OpenAI-style server: Ollama, LM Studio, llama.cpp,
                     vLLM, OpenRouter, DeepSeek... (stdlib urllib)
  deepl              DeepL v2 API (stdlib urllib)
"""

import json
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

DEFAULT_MODELS = {
    'anthropic': 'claude-opus-5-5',
    'openai': 'gpt-5-mini',
    'openai-compatible': '',
    'deepl': '',
}

# Models that accept the server-side refusal fallback ("fallbacks": "default")
ANTHROPIC_FALLBACK_MODELS = {'claude-opus-5-5', 'claude-opus-5', 'claude-fable-5-1', 'claude-sonnet-5-5'}


@dataclass
class Line:
    id: str
    text: str
    name: str = ''


# =============================================================================
# Prompting
# =============================================================================

def build_system_prompt(target_lang: str, glossary: str = '', style_guide: str = '',
                        notes: str = '') -> str:
    parts = [
        f"You translate Japanese visual novel scripts into natural, fluent {target_lang}.",
        "",
        "How the input is given:",
        "- `context` lines come before the lines to translate, for continuity only. "
        "Some may already have a `translation`; stay consistent with it.",
        "- `lines` are the lines to translate. Each has an `id`, an optional `speaker` "
        "(the Japanese name shown in the name plate) and the Japanese `text`. "
        "Lines without a speaker are narration or the protagonist's thoughts.",
        "",
        "How to translate:",
        "- Read the whole chunk first. Japanese often omits subjects; use the speakers "
        "and surrounding lines to decide who is speaking and who is being talked about.",
        "- Keep each character's voice and register consistent. Keep honorifics only if "
        "the style guide says so.",
        "- Keep the sentence boundaries of each line: one output line per input line, "
        "never merge or split lines across ids.",
        "- Keep dialogue brackets: 「」 become double quotes, 『』 become single quotes "
        "(unless the style guide says otherwise); （） inner thoughts become parentheses.",
        "- Ignore the Japanese line breaks and the full-width indentation; they are "
        "layout only. Do not insert line breaks except where the original has a blank line.",
        "- Codes starting with # (for example #姓 #名 #［ #］ #強) are engine commands. "
        "Copy them unchanged into the translation at the matching position. Never write a "
        "# character otherwise.",
        "- Do not add translator notes or explanations.",
    ]
    if glossary:
        parts += ["", "Glossary (use these renderings exactly):", glossary]
    if style_guide:
        parts += ["", "Style guide from the translation team:", style_guide]
    if notes:
        parts += ["", notes]
    return '\n'.join(parts)


def build_user_payload(lines: List[Line], context: List[dict]) -> str:
    payload = {
        'context': context,
        'lines': [{'id': l.id, **({'speaker': l.name} if l.name else {}), 'text': l.text}
                  for l in lines],
    }
    return ("Translate every item in `lines`. Return JSON of the form "
            '{"translations": [{"id": "...", "text": "..."}]} with exactly one entry per id.\n\n'
            + json.dumps(payload, ensure_ascii=False, indent=1))


RESULT_SCHEMA = {
    'type': 'object',
    'properties': {
        'translations': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {'id': {'type': 'string'}, 'text': {'type': 'string'}},
                'required': ['id', 'text'],
                'additionalProperties': False,
            },
        },
    },
    'required': ['translations'],
    'additionalProperties': False,
}


def parse_result(text: str) -> Dict[str, str]:
    text = text.strip()
    m = re.search(r'\{.*\}', text, re.S)
    if m:
        text = m.group(0)
    data = json.loads(text)
    return {str(t['id']): t.get('text', '') for t in data.get('translations', [])}


# =============================================================================
# HTTP helper (OpenAI / DeepL backends)
# =============================================================================

class APIError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f'HTTP {status}: {body[:500]}')
        self.status = status


def http_json(url: str, body: dict, headers: Dict[str, str], timeout: int = 300,
              retries: int = 6) -> dict:
    data = json.dumps(body).encode('utf-8')
    hdrs = {'Content-Type': 'application/json', **headers}
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode('utf-8', 'replace') if e.fp else ''
            retryable = e.code in (408, 409, 429) or e.code >= 500
            if not retryable or attempt == retries:
                raise APIError(e.code, body_txt)
            wait = e.headers.get('retry-after') if e.headers else None
            delay = float(wait) if wait and wait.replace('.', '').isdigit() else min(60, 2 ** attempt)
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == retries:
                raise
            delay = min(60, 2 ** attempt)
        time.sleep(delay + random.uniform(0, 1))
    raise RuntimeError('unreachable')


# =============================================================================
# Backends
# =============================================================================

class Backend:
    supports_chunks = True

    def __init__(self, api_key: str = '', model: str = '', base_url: str = '',
                 target_lang: str = 'English', effort: str = 'medium'):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.target_lang = target_lang
        self.effort = effort
        self.usage = {'input': 0, 'output': 0, 'cache_read': 0}

    def translate_chunk(self, system: str, lines: List[Line], context: List[dict]) -> Dict[str, str]:
        raise NotImplementedError

    def complete_json(self, system: str, prompt: str, schema: dict) -> dict:
        raise NotImplementedError


class AnthropicBackend(Backend):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.model = self.model or DEFAULT_MODELS['anthropic']
        try:
            import anthropic
        except ImportError:
            raise RuntimeError('The anthropic backend needs the SDK: pip install anthropic')
        self._anthropic = anthropic
        args = {'max_retries': 6}
        if self.api_key:
            args['api_key'] = self.api_key
        if self.base_url:
            args['base_url'] = self.base_url
        self.client = anthropic.Anthropic(**args)

    def request_params(self, system: str, user: str, schema: dict) -> dict:
        return {
            'model': self.model,
            'max_tokens': 16000,
            'system': [{'type': 'text', 'text': system, 'cache_control': {'type': 'ephemeral'}}],
            'messages': [{'role': 'user', 'content': user}],
            'output_config': {
                'effort': self.effort,
                'format': {'type': 'json_schema', 'schema': schema},
            },
        }

    def _create(self, params: dict):
        if self.model in ANTHROPIC_FALLBACK_MODELS and not self.base_url:
            resp = self.client.beta.messages.create(
                betas=['server-side-fallback-2026-07-01'], fallbacks='default', **params)
        else:
            resp = self.client.messages.create(**params)
        u = resp.usage
        self.usage['input'] += u.input_tokens or 0
        self.usage['output'] += u.output_tokens or 0
        self.usage['cache_read'] += getattr(u, 'cache_read_input_tokens', 0) or 0
        if resp.stop_reason == 'refusal':
            raise RuntimeError('model declined this chunk (refusal)')
        if resp.stop_reason == 'max_tokens':
            raise RuntimeError('output hit max_tokens; use a smaller --chunk-size')
        return next((b.text for b in resp.content if b.type == 'text'), '')

    def translate_chunk(self, system, lines, context):
        return parse_result(self._create(self.request_params(
            system, build_user_payload(lines, context), RESULT_SCHEMA)))

    def complete_json(self, system, prompt, schema):
        return json.loads(self._create(self.request_params(system, prompt, schema)))

    # ---- Message Batches (50% cheaper, asynchronous) ----
    def translate_batch(self, system: str, jobs: List[tuple], poll: int = 30,
                        log: Callable[[str], None] = print) -> Dict[str, Dict[str, str]]:
        """jobs: [(custom_id, lines, context)] -> {custom_id: {line_id: text}}"""
        from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
        from anthropic.types.messages.batch_create_params import Request
        requests = [
            Request(custom_id=cid, params=MessageCreateParamsNonStreaming(
                **self.request_params(system, build_user_payload(lines, ctx), RESULT_SCHEMA)))
            for cid, lines, ctx in jobs
        ]
        batch = self.client.messages.batches.create(requests=requests)
        log(f'Submitted batch {batch.id} with {len(requests)} chunks')
        while True:
            batch = self.client.messages.batches.retrieve(batch.id)
            if batch.processing_status == 'ended':
                break
            c = batch.request_counts
            log(f'  batch {batch.processing_status}: {c.succeeded} done, {c.processing} processing')
            time.sleep(poll)
        out: Dict[str, Dict[str, str]] = {}
        for r in self.client.messages.batches.results(batch.id):
            if r.result.type != 'succeeded':
                log(f'  chunk {r.custom_id}: {r.result.type}')
                continue
            msg = r.result.message
            if msg.stop_reason in ('refusal', 'max_tokens'):
                log(f'  chunk {r.custom_id}: stop_reason={msg.stop_reason}')
                continue
            text = next((b.text for b in msg.content if b.type == 'text'), '')
            try:
                out[r.custom_id] = parse_result(text)
            except (ValueError, KeyError) as e:
                log(f'  chunk {r.custom_id}: bad JSON ({e})')
        return out


class OpenAIBackend(Backend):
    def __init__(self, compatible: bool = False, **kw):
        super().__init__(**kw)
        self.compatible = compatible
        self.base_url = (self.base_url or ('http://localhost:11434/v1' if compatible
                                           else 'https://api.openai.com/v1')).rstrip('/')
        self.model = self.model or DEFAULT_MODELS['openai']
        if compatible and not kw.get('model'):
            raise RuntimeError('--model is required for openai-compatible servers')

    def _chat(self, system: str, user: str, schema: Optional[dict]) -> str:
        body = {
            'model': self.model,
            'messages': [{'role': 'system', 'content': system},
                         {'role': 'user', 'content': user}],
        }
        if schema and not self.compatible:
            body['response_format'] = {'type': 'json_schema', 'json_schema': {
                'name': 'result', 'schema': schema, 'strict': True}}
        else:
            body['response_format'] = {'type': 'json_object'}
        headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
        try:
            res = http_json(f'{self.base_url}/chat/completions', body, headers)
        except APIError as e:
            if e.status == 400 and 'response_format' in str(e):
                body.pop('response_format')
                res = http_json(f'{self.base_url}/chat/completions', body, headers)
            else:
                raise
        u = res.get('usage') or {}
        self.usage['input'] += u.get('prompt_tokens', 0)
        self.usage['output'] += u.get('completion_tokens', 0)
        return res['choices'][0]['message']['content'] or ''

    def translate_chunk(self, system, lines, context):
        return parse_result(self._chat(system, build_user_payload(lines, context), RESULT_SCHEMA))

    def complete_json(self, system, prompt, schema):
        txt = self._chat(system, prompt, schema)
        m = re.search(r'\{.*\}', txt, re.S)
        return json.loads(m.group(0) if m else txt)


DEEPL_LANGS = {
    'english': 'EN-US', 'british english': 'EN-GB', 'portuguese': 'PT-BR', 'spanish': 'ES',
    'french': 'FR', 'german': 'DE', 'italian': 'IT', 'russian': 'RU', 'chinese': 'ZH-HANS',
    'traditional chinese': 'ZH-HANT', 'korean': 'KO', 'polish': 'PL', 'indonesian': 'ID',
    'vietnamese': 'VI', 'turkish': 'TR', 'ukrainian': 'UK', 'dutch': 'NL',
}


class DeepLBackend(Backend):
    """DeepL: no speaker awareness, but sends preceding lines as `context`."""

    def __init__(self, **kw):
        super().__init__(**kw)
        free = self.api_key.endswith(':fx')
        self.base_url = self.base_url or ('https://api-free.deepl.com/v2' if free
                                          else 'https://api.deepl.com/v2')
        self.lang = DEEPL_LANGS.get(self.target_lang.lower(), self.target_lang.upper())

    def translate_chunk(self, system, lines, context):
        ctx = '\n'.join(c['text'] for c in context)
        body = {'text': [l.text for l in lines], 'source_lang': 'JA',
                'target_lang': self.lang, 'preserve_formatting': True}
        if ctx:
            body['context'] = ctx
        res = http_json(f'{self.base_url}/translate', body,
                        {'Authorization': f'DeepL-Auth-Key {self.api_key}'})
        return {l.id: t['text'] for l, t in zip(lines, res['translations'])}


def make_backend(api: str, **kw) -> Backend:
    if api == 'anthropic':
        return AnthropicBackend(**kw)
    if api == 'openai':
        return OpenAIBackend(compatible=False, **kw)
    if api == 'openai-compatible':
        return OpenAIBackend(compatible=True, **kw)
    if api == 'deepl':
        return DeepLBackend(**kw)
    raise ValueError(f'unknown api {api}')


API_KEY_ENV = {'openai': 'OPENAI_API_KEY', 'anthropic': 'ANTHROPIC_API_KEY',
               'deepl': 'DEEPL_API_KEY', 'openai-compatible': 'OPENAI_API_KEY'}


# =============================================================================
# Driver
# =============================================================================

class ChunkTranslator:
    """Translate a list of Lines in chunks with surrounding context."""

    def __init__(self, backend: Backend, chunk_size: int = 30, context_lines: int = 8,
                 glossary: str = '', style_guide: str = '', notes: str = '',
                 log: Callable[[str], None] = print):
        self.backend = backend
        self.chunk_size = chunk_size
        self.context_lines = context_lines
        self.system = build_system_prompt(backend.target_lang, glossary, style_guide, notes)
        self.log = log

    def _context(self, all_lines: List[Line], start: int, done: Dict[str, str]) -> List[dict]:
        ctx = []
        for l in all_lines[max(0, start - self.context_lines):start]:
            item = {'text': l.text}
            if l.name:
                item['speaker'] = l.name
            if done.get(l.id):
                item['translation'] = done[l.id]
            ctx.append(item)
        return ctx

    def _translate_with_split(self, lines: List[Line], ctx: List[dict]) -> Dict[str, str]:
        try:
            res = self.backend.translate_chunk(self.system, lines, ctx)
        except (ValueError, KeyError, RuntimeError) as e:
            if len(lines) == 1:
                self.log(f'    {lines[0].id}: failed ({e})')
                return {}
            self.log(f'    chunk failed ({e}); splitting')
            res = {}
        missing = [l for l in lines if not res.get(l.id)]
        if missing and len(lines) > 1:
            half = max(1, len(missing) // 2)
            for part in (missing[:half], missing[half:]):
                if part:
                    res.update(self._translate_with_split(part, ctx))
        return res

    def translate(self, lines: List[Line], done: Optional[Dict[str, str]] = None,
                  on_progress: Optional[Callable[[Dict[str, str]], None]] = None) -> Dict[str, str]:
        done = dict(done or {})
        todo_idx = [i for i, l in enumerate(lines) if not done.get(l.id) and l.text.strip()]
        n = 0
        while n < len(todo_idx):
            start = todo_idx[n]
            chunk_idx = todo_idx[n:n + self.chunk_size]
            chunk = [lines[i] for i in chunk_idx]
            ctx = self._context(lines, start, done)
            res = self._translate_with_split(chunk, ctx)
            done.update({k: v for k, v in res.items() if v})
            n += len(chunk_idx)
            self.log(f'  {n}/{len(todo_idx)} lines')
            if on_progress:
                on_progress(done)
        return done

    def translate_batch_api(self, files: List[tuple]) -> Dict[str, Dict[str, str]]:
        """files: [(file_key, lines, done)] -> {file_key: {id: text}} using Message Batches."""
        if not isinstance(self.backend, AnthropicBackend):
            raise RuntimeError('--batch-api is only available with --api anthropic')
        jobs = []
        index = {}
        for fi, (key, lines, done) in enumerate(files):
            todo = [i for i, l in enumerate(lines) if not done.get(l.id) and l.text.strip()]
            for ci in range(0, len(todo), self.chunk_size):
                idxs = todo[ci:ci + self.chunk_size]
                cid = f'f{fi}c{ci // self.chunk_size}'
                # previous original lines only (translations are not known yet)
                ctx = [{'text': l.text, **({'speaker': l.name} if l.name else {})}
                       for l in lines[max(0, idxs[0] - self.context_lines):idxs[0]]]
                jobs.append((cid, [lines[i] for i in idxs], ctx))
                index[cid] = key
        if not jobs:
            return {}
        results = self.backend.translate_batch(self.system, jobs, log=self.log)
        out: Dict[str, Dict[str, str]] = {}
        for cid, res in results.items():
            out.setdefault(index[cid], {}).update(res)
        return out


# =============================================================================
# Glossary bootstrap
# =============================================================================

GLOSSARY_SCHEMA = {
    'type': 'object',
    'properties': {
        'terms': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'source': {'type': 'string'},
                    'target': {'type': 'string'},
                    'kind': {'type': 'string', 'enum': ['character', 'place', 'term', 'other']},
                    'note': {'type': 'string'},
                },
                'required': ['source', 'target', 'kind', 'note'],
                'additionalProperties': False,
            },
        },
    },
    'required': ['terms'],
    'additionalProperties': False,
}

KATAKANA_RE = re.compile(r'[ァ-ヺー]{3,}')
KANJI_NAME_RE = re.compile(r'[一-鿿]{2,4}(?=(?:さん|様|さま|君|くん|ちゃん|先生|先輩))')


def candidate_terms(lines: List[Line], limit: int = 150) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for l in lines:
        if l.name:
            counts[l.name] = counts.get(l.name, 0) + 3
        for m in KATAKANA_RE.findall(l.text) + KANJI_NAME_RE.findall(l.text):
            counts[m] = counts.get(m, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    return dict(ranked[:limit])


def build_glossary(backend: Backend, lines: List[Line], extra_names: List[str] = (),
                   sample_lines: int = 400) -> List[dict]:
    cands = candidate_terms(lines)
    for n in extra_names:
        cands.setdefault(n, 1)
    sample = '\n'.join((f'{l.name}: ' if l.name else '') + l.text.replace('\n', '')
                       for l in lines[:sample_lines])
    system = (f'You build glossaries for translating Japanese visual novels into {backend.target_lang}. '
              'Character names use the romanization a professional localization would use '
              '(Hepburn, given-name order as written, no macrons unless the name is a word). '
              'Drop candidates that are ordinary words, onomatopoeia or grammar.')
    prompt = ('Candidate terms with frequency:\n'
              + json.dumps(cands, ensure_ascii=False)
              + '\n\nScript sample for context:\n' + sample
              + '\n\nReturn the glossary as JSON {"terms": [...]}. For characters, put gender, '
                'role and how they speak in `note`.')
    data = backend.complete_json(system, prompt, GLOSSARY_SCHEMA)
    return data.get('terms', [])
