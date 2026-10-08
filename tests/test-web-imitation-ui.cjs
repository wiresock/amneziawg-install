// Run the actual inline UI script with status responses; no browser or server
// dependencies are needed to guard the configured/running presentation.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../amneziawg-web/src/web/imitation.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

async function render(status) {
    const elements = new Map();
    const document = {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {
                hidden: true, disabled: true, value: '', textContent: '', addEventListener() {},
            });
            return elements.get(id);
        },
    };
    vm.runInNewContext(script, {
        document, URLSearchParams, window: { location: { search: '' } },
        fetch: async () => ({ ok: true, json: async () => status }),
    });
    await new Promise(setImmediate);
    return elements;
}

for (const [service, daemon, expected] of [
    ['inactive', 'stopped', 'stopped'],
    ['failed', 'stopped', 'failed'],
    ['activating', 'stopped', 'activating'],
    ['deactivating', 'stopped', 'deactivating'],
    ['active', 'unverified', 'unverified'],
    [null, 'stopped', 'unknown'],
]) {
    test(`running imitation reports ${expected} for service ${service}`, async () => {
        const elements = await render({
            backend: 'boringtun', protocol: '3.1', service_state: service, daemon_state: daemon,
            imitation: { protocol: 'quic', domain: 'example.com' }, daemon_imitation: null,
        });
        assert.equal(elements.get('imitation-configured').textContent, 'Configured: QUIC · example.com');
        assert.equal(elements.get('imitation-running').textContent, `Running: not verified (${expected})`);
    });
}

test('verified running imitation stays distinct from saved settings', async () => {
    const elements = await render({
        backend: 'boringtun', protocol: '3.1', service_state: 'active', daemon_state: 'running',
        imitation: { protocol: 'quic', domain: 'example.com' },
        daemon_imitation: { protocol: 'dns', domain: '' },
    });
    assert.equal(elements.get('imitation-configured').textContent, 'Configured: QUIC · example.com');
    assert.equal(elements.get('imitation-running').textContent, 'Running: DNS · automatic hostname');
});

const AUTO = { protocol: 'auto', domain: '' };

test('configured and running auto are shown as such, without per-peer claims', async () => {
    const elements = await render({
        backend: 'boringtun', protocol: '2.0', service_state: 'active', daemon_state: 'running',
        imitation: AUTO, daemon_imitation: AUTO, imitation_auto_support: 'supported',
    });
    assert.equal(elements.get('imitation-configured').textContent, 'Configured: Auto · chosen per authenticated peer');
    assert.equal(elements.get('imitation-running').textContent, 'Running: Auto · chosen per authenticated peer');
    assert.doesNotMatch(elements.get('imitation-running').textContent, /learned|DNS|QUIC|SIP|STUN/);
    assert.equal(elements.get('imitation-mode').value, 'auto');
    assert.equal(elements.get('imitation-mode-auto').disabled, false);
    assert.equal(elements.get('imitation-hostname').hidden, true);
    assert.equal(elements.get('imitation-domain').disabled, true);
    const hint = elements.get('imitation-hint').textContent;
    assert.match(hint, /authenticated/);
    assert.match(hint, /recognizable/);
    assert.match(hint, /does not detect S1–S4 or H1–H4/);
    assert.match(hint, /best effort/);
    assert.match(hint, /also fits this server's AWG S\/H framing counts as AWG traffic, not as a hint/);
    assert.match(hint, /A working connection, and Auto shown as running, do not show that a client is imitated/);
    assert.doesNotMatch(hint, /%|guarantee/);
});

test('auto under AWG 3.x states the header-protection consequences', async () => {
    const elements = await render({
        backend: 'boringtun', protocol: '3.1', service_state: 'active', daemon_state: 'running',
        imitation: AUTO, daemon_imitation: AUTO, imitation_auto_support: 'supported',
    });
    const hint = elements.get('imitation-hint').textContent;
    assert.match(hint, /learned DNS or STUN reduces header-masking nonce space/);
    assert.match(hint, /learned SIP is not activated/);
    assert.match(hint, /random padding/);
});

for (const [support, guidance] of [
    ['unsupported', /--upgrade-boringtun/],
    ['unknown', /could not be confirmed/],
    [undefined, /does not report Auto support/],
]) {
    test(`auto is unavailable when the installed support is ${support}`, async () => {
        const status = {
            backend: 'boringtun', protocol: '2.0', service_state: 'active', daemon_state: 'running',
            imitation: { protocol: 'dns', domain: '' }, daemon_imitation: { protocol: 'dns', domain: '' },
        };
        if (support) status.imitation_auto_support = support;
        const elements = await render(status);
        assert.equal(elements.get('imitation-mode-auto').disabled, true);
        assert.match(elements.get('imitation-auto-note').textContent, guidance);
        assert.equal(elements.get('imitation-auto-note').hidden, false);
        assert.equal(elements.get('imitation-fields').disabled, false);
    });
}

test('auto is offered when supported, with the note hidden', async () => {
    const elements = await render({
        backend: 'boringtun', protocol: '2.0', service_state: 'inactive', daemon_state: 'stopped',
        imitation: { protocol: 'none', domain: '' }, daemon_imitation: null, imitation_auto_support: 'supported',
    });
    assert.equal(elements.get('imitation-mode-auto').disabled, false);
    assert.equal(elements.get('imitation-auto-note').hidden, true);
});
