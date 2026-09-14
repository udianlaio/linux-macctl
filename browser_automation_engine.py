#!/usr/bin/env python3
"""R4 browser production automation pure contracts.

This module deliberately contains no SSH, GUI, CDP socket, or filesystem side effects.
It builds bounded DOM expressions and validates automation inputs so the live CLI can
remain fail-closed without exposing arbitrary JavaScript evaluation.
"""
from __future__ import annotations

import json
import re

AUTOMATION_SCHEMA = "macctl-browser-automation/v1"
WAIT_STATES = {"present", "visible", "absent"}
EXTRACT_MODES = {"summary", "text", "links", "forms", "interactive", "full"}
_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")

KEY_SPECS = {
    "Enter": {"key":"Enter","code":"Enter","windowsVirtualKeyCode":13},
    "Escape": {"key":"Escape","code":"Escape","windowsVirtualKeyCode":27},
    "Tab": {"key":"Tab","code":"Tab","windowsVirtualKeyCode":9},
    "Backspace": {"key":"Backspace","code":"Backspace","windowsVirtualKeyCode":8},
    "Delete": {"key":"Delete","code":"Delete","windowsVirtualKeyCode":46},
    "ArrowUp": {"key":"ArrowUp","code":"ArrowUp","windowsVirtualKeyCode":38},
    "ArrowDown": {"key":"ArrowDown","code":"ArrowDown","windowsVirtualKeyCode":40},
    "ArrowLeft": {"key":"ArrowLeft","code":"ArrowLeft","windowsVirtualKeyCode":37},
    "ArrowRight": {"key":"ArrowRight","code":"ArrowRight","windowsVirtualKeyCode":39},
    "Home": {"key":"Home","code":"Home","windowsVirtualKeyCode":36},
    "End": {"key":"End","code":"End","windowsVirtualKeyCode":35},
    "PageUp": {"key":"PageUp","code":"PageUp","windowsVirtualKeyCode":33},
    "PageDown": {"key":"PageDown","code":"PageDown","windowsVirtualKeyCode":34},
    "Space": {"key":" ","code":"Space","windowsVirtualKeyCode":32},
}
MODIFIER_BITS = {"alt":1,"ctrl":2,"control":2,"meta":4,"command":4,"cmd":4,"shift":8}


class BrowserAutomationError(ValueError):
    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason if detail is None else f"{reason}:{detail}")
        self.reason = reason
        self.detail = detail


def _selector(value: str) -> str:
    value = str(value or "").strip()
    if not value or len(value) > 2048 or "\x00" in value:
        raise BrowserAutomationError("invalid_selector")
    return value


def normalize_extract_request(*, mode: str="summary", selector: str|None=None, max_chars: int=65536, max_items: int=100) -> dict:
    mode = str(mode or "summary").strip().lower()
    if mode not in EXTRACT_MODES:
        raise BrowserAutomationError("invalid_extract_mode")
    sel = _selector(selector) if selector is not None else None
    chars = int(max_chars)
    items = int(max_items)
    if chars < 256 or chars > 262144:
        raise BrowserAutomationError("invalid_extract_max_chars")
    if items < 1 or items > 500:
        raise BrowserAutomationError("invalid_extract_max_items")
    return {"schema":AUTOMATION_SCHEMA,"mode":mode,"selector":sel,"max_chars":chars,"max_items":items}


def dom_extract_expression(*, mode: str="summary", selector: str|None=None, max_chars: int=65536, max_items: int=100) -> str:
    req = normalize_extract_request(mode=mode, selector=selector, max_chars=max_chars, max_items=max_items)
    mode_js=json.dumps(req["mode"])
    sel_js=json.dumps(req["selector"])
    return f"""(() => {{
 const mode={mode_js}, sel={sel_js}, maxChars={req['max_chars']}, maxItems={req['max_items']};
 const root=sel===null?(document.body||document.documentElement):document.querySelector(sel);
 if(!root) return {{ok:false,reason:'selector_not_found'}};
 const clip=(v)=>String(v??'').slice(0,maxChars);
 const itemClip=(v)=>String(v??'').slice(0,Math.min(maxChars,2048));
 const arr=(q)=>Array.from(root.querySelectorAll(q)).slice(0,maxItems);
 const visible=(e)=>{{const r=e.getBoundingClientRect();const s=getComputedStyle(e);return !!(r.width||r.height)&&s.visibility!=='hidden'&&s.display!=='none';}};
 const safeUrl=(v)=>{{if(!v)return null;try{{const u=new URL(v,location.href);return u.origin+u.pathname;}}catch(_e){{return null;}}}};
 const sensitive=(e)=>{{const t=String(e.getAttribute&&e.getAttribute('type')||'').toLowerCase();const ac=String(e.getAttribute&&e.getAttribute('autocomplete')||'').toLowerCase();return t==='password'||t==='hidden'||['current-password','new-password','one-time-code','cc-number','cc-csc'].includes(ac);}};
 const out={{ok:true,title:clip(document.title),url:safeUrl(location.href),readyState:document.readyState}};
 if(mode==='summary'||mode==='text'||mode==='full') out.text=clip(root.innerText||root.textContent||'');
 if(mode==='links'||mode==='full') out.links=arr('a[href]').map(e=>({{text:itemClip(e.innerText||e.textContent||''),href:safeUrl(e.href)}}));
 if(mode==='forms'||mode==='full') out.forms=arr('form').map(f=>({{action:safeUrl(f.action||null),method:(f.method||'get').toLowerCase(),name:f.getAttribute('name')||null,id:f.id||null}}));
 if(mode==='interactive'||mode==='full') out.interactive=arr('a[href],button,input,textarea,select,[role="button"],[contenteditable="true"]').map(e=>{{const redacted=sensitive(e);return {{tag:e.tagName,role:e.getAttribute('role'),type:e.getAttribute('type'),autocomplete:e.getAttribute('autocomplete'),name:e.getAttribute('name'),id:e.id||null,text:itemClip(e.innerText||e.textContent||''),value:('value' in e&&!redacted?itemClip(e.value):null),valueRedacted:redacted,disabled:!!e.disabled,visible:visible(e)}};}});
 return out;
}})()"""


def normalize_wait_request(*, selector: str, state: str="present", expect_text: str|None=None, expect_value: str|None=None) -> dict:
    sel=_selector(selector)
    state=str(state or "present").strip().lower()
    if state not in WAIT_STATES:
        raise BrowserAutomationError("invalid_wait_state")
    if expect_text is not None and len(str(expect_text)) > 8192:
        raise BrowserAutomationError("wait_expect_text_too_large")
    if expect_value is not None and len(str(expect_value)) > 8192:
        raise BrowserAutomationError("wait_expect_value_too_large")
    if state == "absent" and (expect_text is not None or expect_value is not None):
        raise BrowserAutomationError("absent_wait_cannot_have_value_expectation")
    return {"schema":AUTOMATION_SCHEMA,"selector":sel,"state":state,"expect_text":expect_text,"expect_value":expect_value}


def dom_wait_probe_expression(*, selector: str, state: str="present", expect_text: str|None=None, expect_value: str|None=None) -> str:
    req=normalize_wait_request(selector=selector,state=state,expect_text=expect_text,expect_value=expect_value)
    return f"""(() => {{
 const s={json.dumps(req['selector'])}, state={json.dumps(req['state'])}, et={json.dumps(req['expect_text'])}, ev={json.dumps(req['expect_value'])};
 const a=Array.from(document.querySelectorAll(s));
 if(state==='absent') return {{ok:true,satisfied:a.length===0,count:a.length}};
 if(a.length!==1) return {{ok:true,satisfied:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0],r=e.getBoundingClientRect(),cs=getComputedStyle(e),vis=!!(r.width||r.height)&&cs.visibility!=='hidden'&&cs.display!=='none';
 const type=String(e.getAttribute&&e.getAttribute('type')||'').toLowerCase(), ac=String(e.getAttribute&&e.getAttribute('autocomplete')||'').toLowerCase();
 const sensitive=(type==='password'||type==='hidden'||['current-password','new-password','one-time-code','cc-number','cc-csc'].includes(ac));
 const text=String(e.innerText||e.textContent||''), value=('value' in e?String(e.value):null);
 let sat=(state==='present')||(state==='visible'&&vis);
 if(et!==null) sat=sat&&text.includes(et);
 if(ev!==null) sat=sat&&value===ev;
 return {{ok:true,satisfied:sat,count:1,visible:vis,text:text.slice(0,8192),value:(value===null||sensitive)?null:value.slice(0,8192),valueRedacted:sensitive}};
}})()"""


def dom_select_expression(selector: str, value: str) -> str:
    sel=_selector(selector)
    value=str(value)
    if len(value) > 16384 or "\x00" in value:
        raise BrowserAutomationError("invalid_select_value")
    return f"""(() => {{
 const s={json.dumps(sel)},v={json.dumps(value, ensure_ascii=False)}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0]; if(e.tagName!=='SELECT') return {{ok:false,count:1,reason:'element_not_select'}};
 if(e.disabled) return {{ok:false,count:1,reason:'element_disabled'}};
 const exists=Array.from(e.options).some(o=>o.value===v); if(!exists) return {{ok:false,count:1,reason:'option_value_not_found'}};
 e.value=v; e.dispatchEvent(new Event('input',{{bubbles:true}})); e.dispatchEvent(new Event('change',{{bubbles:true}}));
 return {{ok:true,count:1,value:e.value}};
}})()"""


def dom_focus_expression(selector: str) -> str:
    sel=_selector(selector)
    return f"""(() => {{ const s={json.dumps(sel)}; const a=Array.from(document.querySelectorAll(s)); if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}}; const e=a[0]; if(e.disabled) return {{ok:false,count:1,reason:'element_disabled'}}; e.focus(); return {{ok:true,count:1,tag:e.tagName}}; }})()"""



def dom_search_probe_expression(selector: str) -> str:
    sel=_selector(selector)
    return f"""(() => {{
 const s={json.dumps(sel)}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0], type=String(e.getAttribute('type')||'').toLowerCase(), role=String(e.getAttribute('role')||'').toLowerCase();
 if(type!=='search'&&role!=='searchbox') return {{ok:false,count:1,reason:'search_input_required'}};
 const f=e.form||e.closest('form'); if(!f) return {{ok:false,count:1,reason:'search_get_form_required'}};
 const method=String(f.method||'get').toLowerCase(); if(method!=='get') return {{ok:false,count:1,reason:'search_get_form_required'}};
 let action=null; try{{const u=new URL(f.action||location.href,location.href);action=u.origin+u.pathname;}}catch(_e){{}}
 return {{ok:true,count:1,method:'get',action:action}};
}})()"""


def dom_value_equals_expression(selector: str, expected: str) -> str:
    sel=_selector(selector)
    expected=str(expected)
    if len(expected) > 16384 or "\x00" in expected:
        raise BrowserAutomationError("invalid_value_expectation")
    return f"""(() => {{ const s={json.dumps(sel)},v={json.dumps(expected, ensure_ascii=False)}; const a=Array.from(document.querySelectorAll(s)); if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}}; const e=a[0]; return {{ok:true,count:1,matches:('value' in e&&String(e.value)===v)}}; }})()"""


def dom_file_input_probe_expression(selector: str) -> str:
    sel=_selector(selector)
    return f"""(() => {{
 const s={json.dumps(sel)}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0]; if(e.tagName!=='INPUT'||String(e.type).toLowerCase()!=='file') return {{ok:false,count:1,reason:'element_not_file_input'}};
 if(e.disabled) return {{ok:false,count:1,reason:'element_disabled'}};
 return {{ok:true,count:1,multiple:!!e.multiple,accept:e.accept||null,fileCount:(e.files?e.files.length:0)}};
}})()"""

def normalize_key_event(key: str, modifiers=None) -> dict:
    key=str(key or "").strip()
    if key not in KEY_SPECS:
        raise BrowserAutomationError("key_not_exposed")
    bits=0
    normalized=[]
    for raw in modifiers or []:
        name=str(raw or "").strip().lower()
        if name not in MODIFIER_BITS:
            raise BrowserAutomationError("invalid_key_modifier", name)
        bit=MODIFIER_BITS[name]
        bits |= bit
        canonical={1:"alt",2:"ctrl",4:"meta",8:"shift"}[bit]
        if canonical not in normalized:
            normalized.append(canonical)
    return {"schema":AUTOMATION_SCHEMA,"key":key,"modifiers":sorted(normalized),"modifier_bits":bits,"cdp":dict(KEY_SPECS[key])}


def history_target(history: dict, direction: str) -> dict:
    direction=str(direction or "").strip().lower()
    if direction not in {"back","forward"}:
        raise BrowserAutomationError("invalid_history_direction")
    try:
        idx=int(history["currentIndex"]); entries=list(history["entries"])
    except Exception as e:
        raise BrowserAutomationError("invalid_navigation_history") from e
    target_idx=idx-1 if direction=="back" else idx+1
    if target_idx < 0 or target_idx >= len(entries):
        raise BrowserAutomationError("navigation_history_boundary")
    item=entries[target_idx]
    try:
        entry_id=int(item["id"]); url=str(item["url"])
    except Exception as e:
        raise BrowserAutomationError("invalid_navigation_history_entry") from e
    return {"schema":AUTOMATION_SCHEMA,"direction":direction,"entry_id":entry_id,"url":url,"target_index":target_idx}
