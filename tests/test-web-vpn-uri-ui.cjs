// Execute the shipped UI script; only browser/network boundaries are doubled.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const sourcePath = path.join(__dirname, '../amneziawg-web/src/web/vpn_uri.html');
const html = fs.existsSync(sourcePath) ? fs.readFileSync(sourcePath, 'utf8') : '';
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] || '';
const URI = 'vpn://AAAAE3jaABC_def-123';

function ui({ clipboard = 'ok', response = async () => ({ ok: true, text: async () => URI }), launchThrows = false } = {}) {
    const elements = new Map();
    const document = {
        activeElement: { focus() {} },
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                hidden: true, value: '', href: '', textContent: '', selected: false,
                focus() { document.activeElement = this; },
                select() { this.selected = true; },
                removeAttribute(name) { this[name] = ''; },
            });
            return elements.get(id);
        },
    };
    const copied = [], opened = [], requests = [];
    const navigator = clipboard === 'absent' ? {} : { clipboard: { async writeText(value) {
        if (clipboard === 'denied') throw new Error('clipboard denied');
        copied.push(value);
    } } };
    const context = vm.createContext({ document, navigator, window: { location: { assign(value) {
        if (launchThrows) throw new Error('no protocol handler');
        opened.push(value);
    } } }, fetch: async (url, options) => { requests.push({ url, options }); return response(); } });
    vm.runInContext(script, context);
    assert.equal(typeof context.exportAmnezia, 'function', 'the export action must be implemented');
    return { context, elements, copied, opened, requests };
}

test('Copy fetches the selected peer on demand without caching and copies only the URI', async () => {
    const page = ui();
    assert.equal(page.requests.length, 0);
    await page.context.exportAmnezia(42, 'copy');
    assert.equal(page.requests[0].url, '/api/peers/42/vpn-uri');
    assert.equal(page.requests[0].options.credentials, 'same-origin');
    assert.equal(page.requests[0].options.cache, 'no-store');
    assert.deepEqual(page.copied, [URI]);
    assert.deepEqual(page.opened, []);
    assert.equal(page.elements.get('amnezia-uri').value, URI);
    assert.match(page.elements.get('amnezia-status').textContent, /copied/i);
});

for (const action of ['copy', 'open']) {
    test(`${action} clears the previous link while a fresh export is pending`, async () => {
        let resolvePending;
        let count = 0;
        const page = ui({ response: () => ++count === 1
            ? { ok: true, text: async () => URI }
            : new Promise(resolve => { resolvePending = resolve; }) });
        await page.context.exportAmnezia(1, 'copy');
        assert.equal(page.elements.get('amnezia-uri').value, URI);
        assert.equal(page.elements.get('amnezia-open-link').href, URI);
        assert.equal(page.elements.get('amnezia-open-link').hidden, false);

        const pending = page.context.exportAmnezia(1, action);
        try {
            assert.equal(page.requests.length, 2);
            assert.match(page.elements.get('amnezia-status').textContent, /preparing/i);
            assert.equal(page.elements.get('amnezia-uri').value, '', 'old credentials must clear before the fetch resolves');
            assert.equal(page.elements.get('amnezia-open-link').href, '', 'the old link must no longer be launchable');
            assert.equal(page.elements.get('amnezia-open-link').hidden, true);
            assert.deepEqual(page.copied, [URI]);
            assert.deepEqual(page.opened, []);
        } finally {
            resolvePending({ ok: true, text: async () => 'vpn://NEW' });
            await pending;
        }
    });
}

for (const clipboard of ['absent', 'denied']) {
    test(`Copy provides a selected manual fallback when clipboard is ${clipboard}`, async () => {
        const page = ui({ clipboard });
        await page.context.exportAmnezia(7, 'copy');
        assert.deepEqual(page.copied, []);
        assert.equal(page.elements.get('amnezia-uri').value, URI);
        assert.equal(page.elements.get('amnezia-uri').selected, true);
        assert.match(page.elements.get('amnezia-status').textContent, /copy.*selected/i);
        assert.doesNotMatch(page.elements.get('amnezia-status').textContent, /link copied/i);
    });
}

test('Open launches the exact URI and leaves a real link for a fresh user gesture', async () => {
    const page = ui();
    await page.context.exportAmnezia(9, 'open');
    assert.deepEqual(page.opened, [URI]);
    assert.equal(page.elements.get('amnezia-open-link').href, URI);
    assert.equal(page.elements.get('amnezia-open-link').hidden, false);
    assert.equal(page.elements.get('amnezia-uri').value, URI);
    assert.doesNotMatch(page.elements.get('amnezia-status').textContent, /successfully opened/i);
});

test('a blocked app launch retains the import link for manual use', async () => {
    const page = ui({ launchThrows: true });
    await page.context.exportAmnezia(9, 'open');
    assert.equal(page.elements.get('amnezia-uri').value, URI);
    assert.equal(page.elements.get('amnezia-open-link').href, URI);
    assert.match(page.elements.get('amnezia-status').textContent, /manually/i);
});

for (const badResponse of [
    async () => ({ ok: false, status: 401, text: async () => 'SECRET' }),
    async () => ({ ok: false, status: 404, text: async () => 'SECRET' }),
    async () => ({ ok: true, text: async () => 'javascript:alert("SECRET")' }),
    async () => { throw new Error('network SECRET'); },
]) {
    test('failed or malformed exports clear old links and never copy or navigate', async () => {
        let fail = false;
        const page = ui({ response: () => fail ? badResponse() : { ok: true, text: async () => URI } });
        await page.context.exportAmnezia(1, 'copy');
        fail = true;
        await page.context.exportAmnezia(2, 'open');
        assert.deepEqual(page.copied, [URI]);
        assert.deepEqual(page.opened, []);
        assert.equal(page.elements.get('amnezia-uri').value, '');
        assert.equal(page.elements.get('amnezia-open-link').href, '');
        assert.equal(page.elements.get('amnezia-open-link').hidden, true);
        assert.doesNotMatch(page.elements.get('amnezia-status').textContent, /SECRET/);
        assert.match(page.elements.get('amnezia-status').textContent, /could not/i);
    });
}

test('an older response cannot override or launch a newer export', async () => {
    let resolveOld;
    let count = 0;
    const page = ui({ response: () => ++count === 1
        ? new Promise(resolve => { resolveOld = resolve; })
        : { ok: true, text: async () => URI } });
    const old = page.context.exportAmnezia(1, 'open');
    await page.context.exportAmnezia(2, 'copy');
    resolveOld({ ok: true, text: async () => 'vpn://OLD' });
    await old;
    assert.equal(page.elements.get('amnezia-uri').value, URI);
    assert.deepEqual(page.opened, []);
    assert.deepEqual(page.copied, [URI]);
});

test('hiding an export clears the secret and discards a pending response', async () => {
    let resolve;
    const page = ui({ response: () => new Promise(done => { resolve = done; }) });
    const pending = page.context.exportAmnezia(1, 'open');
    page.context.hideAmneziaLink();
    resolve({ ok: true, text: async () => URI });
    await pending;
    assert.equal(page.elements.get('amnezia-export').hidden, true);
    assert.equal(page.elements.get('amnezia-uri').value, '');
    assert.equal(page.elements.get('amnezia-open-link').href, '');
    assert.deepEqual(page.opened, []);
});
