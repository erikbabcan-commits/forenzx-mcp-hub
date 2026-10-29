'use strict';

// Scope: source checks and the real inline JS executed with an in-memory DOM
// adapter. This is not browser rendering, browser security or a Windows test.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const html = fs.readFileSync(path.join(__dirname, '../preview/index.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1);
const code = scripts[0][1];
new vm.Script(code);
assert(html.includes('youh4ck3dme | lockdown'));
assert(html.includes("connect-src 'none'"));
assert(html.includes("form-action 'none'"));
assert(!/\s(?:src|href|action)\s*=/i.test(html));
assert(!/@import|url\s*\(/i.test(html));
assert(!/\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage|indexedDB|serviceWorker)\b/.test(code));
assert(!/console\.|document\.cookie|['"]keydown['"]|['"]keyup['"]/.test(code));

class Element {
    constructor() {
        this.handlers = new Map();
        this.attrs = new Map();
        this.hidden = false;
        this.disabled = false;
        this.value = '';
        this.textContent = '';
        this.children = [];
        this.dataset = {};
        this.classList = { add() {} };
    }
    addEventListener(type, fn) { this.handlers.set(type, fn); }
    setAttribute(key, value) { this.attrs.set(key, value); }
    removeAttribute(key) { this.attrs.delete(key); }
    append(child) { this.children.push(child); }
    replaceChildren(...children) { this.children = children; }
    focus() {}
    click() { return this.emit('click', {}); }
    emit(type, event) { return this.handlers.get(type)?.(event); }
}

const nodes = new Map();
const references = [];
for (const match of html.matchAll(/<[^>]+\bid="([^"]+)"[^>]*>/g)) {
    assert(!nodes.has(match[1]), 'duplicate element ID');
    const node = new Element();
    node.hidden = /\shidden(?:\s|>)/.test(match[0]);
    nodes.set(match[1], node);
}
for (const match of html.matchAll(/\b(?:for|aria-labelledby|aria-describedby)="([^"]+)"/g)) {
    references.push(...match[1].split(/\s+/));
}
for (const reference of references) assert(nodes.has(reference));

const words = [...html.matchAll(/data-pixel="([^"]+)"/g)].map(match => {
    const word = new Element();
    word.dataset.pixel = match[1];
    return word;
});
const document = new Element();
const window = new Element();
document.getElementById = id => { assert(nodes.has(id)); return nodes.get(id); };
document.querySelectorAll = selector => selector === '[data-pixel]' ? words : [];
document.createElementNS = () => new Element();
document.fullscreenEnabled = false;
vm.runInNewContext(code, { document, window, matchMedia: () => ({matches: true}), setTimeout }, {timeout: 1000});

const form = nodes.get('unlock-form');
const field = nodes.get('demo-password');
const success = nodes.get('success');
const submit = () => form.emit('submit', { preventDefault() {} });

(async () => {
    console.log('PASS: JavaScript syntax, labels, pixel glyph generation and expected title');
    console.log('PASS: no external resources, storage, logging or global keyboard hooks in source');
    assert.equal(success.hidden, true);
    field.value = '';
    await submit();
    assert.equal(success.hidden, true);
    console.log('PASS: empty input leaves the demo in its initial state');
    field.value = 'non-secret-demo-one';
    await submit();
    assert.equal(success.hidden, false);
    assert.equal(form.hidden, true);
    assert.equal(field.value, '');
    console.log('PASS: nonempty test input plays the preview and is cleared');
    nodes.get('reset').click();
    assert.equal(success.hidden, true);
    assert.equal(form.hidden, false);
    assert.equal(field.disabled, false);
    console.log('PASS: reset restores the form');
    field.value = 'different-public-test-text';
    await submit();
    assert.equal(success.hidden, false);
    console.log('PASS: different arbitrary input is also accepted; confirms demo, not authentication');
    field.value = 'temporary-public-test-text';
    window.emit('pagehide', {});
    assert.equal(field.value, '');
    window.emit('pageshow', {persisted: true});
    assert.equal(success.hidden, true);
    assert.equal(form.hidden, false);
    console.log('PASS: page lifecycle clears input and resets the restored page');
    console.log('NOT_VERIFIED: rendering, fullscreen permissions, real Windows lock, boot/logon and deployment');
})().catch(error => {
    console.error('FAIL: ' + error.message);
    process.exitCode = 1;
});
