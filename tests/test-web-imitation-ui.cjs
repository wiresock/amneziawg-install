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
