"""Deterministic prompt-injection rules.

IMPORTANT: pattern matching cannot reliably catch every prompt injection. These rules
find KNOWN phrasings and structures. Paraphrases, other languages (beyond the small set
below), and instructions that never name the AI will get through. Treat a hit as one
signal for the policy engine, and a miss as meaningless.

Rules are source-aware. `sources=None` means "any source". Rules limited to
non-user sources capture the key idea of INDIRECT injection: a retrieved document,
web page or tool output has no business giving instructions, so imperatives aimed at
the AI are suspicious there even though the same sentence is a normal request from a user.

False-positive notes are next to the rules most likely to cause them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from guardrails.detectors.base import Rule
from guardrails.types import Confidence, ContentSource, ReasonCode, Severity

C = ContentSource
S = Severity
CF = Confidence
INDIRECT = frozenset({C.RETRIEVED_DOCUMENT, C.WEB_PAGE, C.UPLOADED_FILE, C.TOOL_OUTPUT, C.MODEL_OUTPUT})


@dataclass(frozen=True)
class InjectionRule:
    rule: Rule
    sources: frozenset[ContentSource] | None = None  # None = every source

    def applies_to(self, source: ContentSource) -> bool:
        return self.sources is None or source in self.sources


def _r(detector_id: str, category: str, severity: Severity, confidence: Confidence, pattern: str, *,
       sources: frozenset[ContentSource] | None = None, reason: ReasonCode = ReasonCode.PROMPT_INJECTION,
       flags: int = re.IGNORECASE, group: int = 0) -> InjectionRule:
    return InjectionRule(
        Rule(detector_id, category, "injection", severity, 50, re.compile(pattern, flags), group,
             None, confidence, reason),
        sources,
    )


# Building blocks. No "my"/"our": "ignore my previous instructions" is a user correcting themselves.
_ART = r"(?:(?:the|your|all|any|every|these|those|of)\s+)*"
_PREV = r"(?:previous|prior|above|earlier|preceding|original|initial|existing|former|past|system|developer|safety)"
_NOUN = r"(?:instructions?|prompts?|rules|guidelines?|directives?|commands?|constraints?|restrictions?|programming|guardrails?|policies|policy)"
_SECRET_NOUN = (r"(?:api[\s_-]?keys?|passwords?(?!\s+(?:requirements?|policy|policies|manager|reset|strength|rules?|hashing"
                r"|complexity|length|field|input|form|protection|best))|credentials?|secrets?|access\s+tokens?"
                r"|auth(?:entication)?\s+tokens?|private\s+keys?|ssh\s+keys?|env(?:ironment)?\s+variables?)")
_SECRET_NOUN_NO_PW = (r"(?:api[\s_-]?keys?|credentials?|secrets?|access\s+tokens?|auth(?:entication)?\s+tokens?"
                      r"|private\s+keys?|ssh\s+keys?|env(?:ironment)?\s+variables?)")
_SHOW = (r"(?:reveal|show|print|display|repeat|output|tell|give|leak|dump|recite|disclose|expose|share|paste"
         r"|provide|send|list|read|extract)")

RULES: tuple[InjectionRule, ...] = (
    # ------------------------------------------------------------------ instruction override
    _r("injection.override.previous", "instruction_override", S.HIGH, CF.HIGH,
       rf"\b(?:ignore|disregard|forget|override|bypass|discard)\s+{_ART}{_PREV}\s+{_NOUN}\b"),
    _r("injection.override.everything", "instruction_override", S.HIGH, CF.HIGH,
       r"\b(?:ignore|forget|disregard)\s+(?:everything|all|anything)\s+(?:above|before\s+this"
       r"|you\s+(?:were|have\s+been|had\s+been)\s+(?:told|instructed|given|trained))"),
    _r("injection.override.your_rules", "instruction_override", S.MEDIUM, CF.MEDIUM,
       r"\b(?:ignore|disregard|bypass|override|disobey|violate)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your|the)\s+"
       r"(?:(?:safety|content|ethical|security)\s+)?(?:instructions?|rules|guidelines|restrictions|guardrails|programming|policies|filters)\b"),
    _r("injection.override.new_instructions", "instruction_override", S.HIGH, CF.MEDIUM,
       r"^\s*(?:new|updated|revised|additional|override)\s+(?:system\s+)?instructions?\s*[:\-]",
       sources=INDIRECT, flags=re.IGNORECASE | re.MULTILINE),
    _r("injection.override.multilingual", "instruction_override", S.HIGH, CF.MEDIUM,
       r"(?:\bignora\s+(?:todas\s+)?las\s+instrucciones\s+anteriores|\bignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+pr[eé]c[eé]dentes"
       r"|\bignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+anweisungen|\bignore\s+(?:todas\s+)?as\s+instru[cç][oõ]es\s+anteriores"
       r"|\bignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti|игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие|прежние)\s+(?:инструкции|указания)"
       r"|تجاهل\s+(?:جميع\s+|كل\s+)?التعليمات\s+السابقة|پچھلی\s+(?:تمام\s+)?ہدایات\s+(?:کو\s+)?نظر\s+انداز\s+کر)"),
    # ------------------------------------------------------------------ jailbreak / persona / policy bypass
    _r("injection.persona.unrestricted", "jailbreak_persona", S.HIGH, CF.HIGH,
       r"\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|DAN)\b"
       r"|\b(?:enable|activate|enter|switch\s+to)\s+(?:jailbreak|DAN|unrestricted)\s+mode\b"
       r"|\bdo\s+anything\s+now\b"
       r"|\bfrom\s+now\s+on,?\s+you\s+(?:are|will\s+be|must\s+act\s+as)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|evil)\b"),
    # "developer mode" is also an ordinary phone/IDE setting, so confidence is low.
    _r("injection.persona.developer_mode", "jailbreak_persona", S.MEDIUM, CF.LOW,
       r"\byou\s+are\s+now\s+in\s+(?:developer|god|sudo)\s+mode\b|\b(?:enable|activate|enter|switch\s+to)\s+(?:developer|god|sudo)\s+mode\b"),
    _r("injection.bypass.no_restrictions", "policy_bypass", S.MEDIUM, CF.MEDIUM,
       r"\b(?:pretend|imagine|roleplay|role-play|act)\b[^.\n]{0,60}?\b(?:no|without|free\s+of)\s+(?:any\s+)?"
       r"(?:restrictions?|rules|filters?|limits|limitations|guidelines|ethics|censorship)\b"
       r"|\byou\s+(?:have|has)\s+no\s+(?:restrictions?|rules|limitations|guidelines|filters)\b"
       r"|\b(?:disable|turn\s+off|deactivate|remove)\s+(?:all\s+)?(?:your\s+)?(?:safety|content\s+polic(?:y|ies)|filters?|guardrails?|restrictions)\b"),
    # ------------------------------------------------------------------ system prompt extraction
    _r("injection.extract.your_system_prompt", "system_prompt_extraction", S.HIGH, CF.HIGH,
       rf"\b{_SHOW}\b[^.\n?]{{0,40}}?\byour\s+(?:(?:system|initial|original|hidden|secret|internal|developer|full|exact|entire|complete)\s+){{1,2}}"
       r"(?:prompt|instructions?|message|rules|configuration|guidelines)\b",
       reason=ReasonCode.SYSTEM_PROMPT_EXTRACTION),
    _r("injection.extract.repeat_above", "system_prompt_extraction", S.HIGH, CF.HIGH,
       r"\b(?:repeat|print|output|recite)\s+(?:everything|all|the\s+text|the\s+words|the\s+content)\s+(?:above|before"
       r"|from\s+the\s+(?:start|beginning))\b", reason=ReasonCode.SYSTEM_PROMPT_EXTRACTION),
    _r("injection.extract.the_system_prompt", "system_prompt_extraction", S.MEDIUM, CF.MEDIUM,
       r"\b(?:reveal|show|print|display|output|repeat|leak|dump)\b[^.\n?]{0,40}?\bthe\s+(?:system|hidden|initial|original|secret)\s+"
       r"(?:prompt|instructions?|message)\b", reason=ReasonCode.SYSTEM_PROMPT_EXTRACTION),
    _r("injection.extract.your_instructions", "system_prompt_extraction", S.LOW, CF.LOW,
       rf"\b{_SHOW}\b[^.\n?]{{0,25}}?\byour\s+(?:prompt|instructions)\b|\bwhat\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions)\b",
       reason=ReasonCode.SYSTEM_PROMPT_EXTRACTION),
    # ------------------------------------------------------------------ credential exfiltration
    # Advice such as "never reveal your password" is not an attack: negated verbs are skipped and
    # "your password(s)" is excluded (a person's own password); "your API keys/secrets" is not.
    _r("injection.exfil.credentials", "credential_exfiltration", S.HIGH, CF.MEDIUM,
       r"(?<!never\s)(?<!not\s)(?<!n't\s)\b(?:" + _SHOW[3:-1] + r"|email|post|upload|forward|include|exfiltrate)\b[^.\n?]{0,50}?\b(?:"
       r"your\s+(?:\w+\s+){0,2}?" + _SECRET_NOUN_NO_PW + r"\b"
       r"|(?:the\s+(?:system|server|admin|root|backend|production|stored|saved|internal|environment)|any|all|every)\s+(?:\w+\s+){0,2}?"
       + _SECRET_NOUN + r"\b)"),
    _r("injection.exfil.markdown_image", "data_exfiltration", S.MEDIUM, CF.LOW,
       r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]{1,200}\?[^)\s]{0,100}(?:=|%3D)[^)\s]{0,40}"
       r"(?:\{|\[|<|%7B|%5B|%3C|data|secret|prompt|history|conversation|summary|password|token|key)",
       sources=INDIRECT),
    # ------------------------------------------------------------------ template / role delimiter injection
    _r("injection.delimiter.chat_template", "role_impersonation", S.HIGH, CF.HIGH,
       r"<\|(?:im_start|im_end|endoftext|system|user|assistant|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<</?SYS>>"),
    _r("injection.delimiter.begin_system", "role_impersonation", S.HIGH, CF.HIGH,
       r"[\[<]?\s*(?:begin|start)\s+(?:of\s+)?(?:new\s+)?(?:system|developer)\s+(?:prompt|instructions?|message)\b"),
    # Low confidence on purpose: pasted transcripts and logs legitimately contain "system:" lines.
    _r("injection.delimiter.role_prefix", "role_impersonation", S.MEDIUM, CF.LOW,
       r"^[ \t]*(?:#{1,3}\s*)?(?:system|assistant|developer)\s*(?:prompt|message)?\s*:", flags=re.IGNORECASE | re.MULTILINE),
    # ------------------------------------------------------------------ INDIRECT injection (non-user sources only)
    _r("injection.indirect.addressed_to_ai", "indirect_instruction", S.HIGH, CF.MEDIUM,
       r"\b(?:ai|a\.i\.|assistant|chatbot|language\s+model|llm|agent|chatgpt|gpt-?\d*|claude|copilot|gemini)\b\s*[,:\-]\s*"
       r"(?:you\s+(?:must|should|need\s+to|are\s+to|will|shall)|please\b|now\b|ignore|disregard|forget|instead|do\s+not|don't|never|always|stop)",
       sources=INDIRECT),
    _r("injection.indirect.note_to_ai", "indirect_instruction", S.HIGH, CF.MEDIUM,
       r"\b(?:important|attention|urgent|note|instructions?)\b\s*(?:for|to)\s+(?:the\s+)?(?:ai|assistant|llm|model|agent|chatbot|language\s+model)\s*[:,\-]",
       sources=INDIRECT),
    _r("injection.indirect.conceal", "indirect_instruction", S.HIGH, CF.MEDIUM,
       r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|alert|notify)\s+(?:the\s+)?(?:user|human|person)\b",
       sources=INDIRECT),
    _r("injection.indirect.send_data", "data_exfiltration", S.HIGH, CF.MEDIUM,
       r"\b(?:send|forward|email|post|upload|transmit|submit|leak|exfiltrate)\b[^.\n]{0,30}?\b(?:conversation|chat\s+history|chat|history"
       r"|user'?s?\s+(?:data|information|messages?|files?|emails?)|system\s+prompt|secrets?|credentials?"
       r"|all\s+(?:the\s+)?(?:data|files|messages)|everything)\b[^.\n]{0,40}?\b(?:to|at|via)\s+(?:\S+@\S+\.\S+|https?://\S+)",
       sources=INDIRECT),
    # Tool output is data. It should never tell the agent what to do next.
    _r("injection.indirect.tool_directive", "tool_output_manipulation", S.MEDIUM, CF.LOW,
       r"\b(?:now|next|then|immediately|first)\b[,:]?\s+(?:you\s+(?:must|should|will|need\s+to)\s+)?(?:call|invoke|run|execute|use|trigger)\b"
       r"[^.\n]{0,40}?\b(?:tool|function|command|shell|terminal|api|script)\b",
       sources=frozenset({C.TOOL_OUTPUT})),
)
