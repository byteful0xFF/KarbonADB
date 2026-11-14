// KarbonADB: wireless ADB (TCP/IP) extension for TurboWarp
// Browsers cannot open raw TCP sockets, so this talks to the headset through a
// tiny local WebSocket->TCP bridge (see bridge.js). Everything else (ADB protocol,
// RSA auth, shell, sync push/pull) is implemented here with no dependencies.
(function (Scratch) {
  'use strict';
  if (!Scratch.extensions.unsandboxed) throw new Error('KarbonADB must run unsandboxed');

  const enc = new TextEncoder(), dec = new TextDecoder();
  const A_CNXN = 0x4e584e43, A_AUTH = 0x48545541, A_OPEN = 0x4e45504f,
        A_OKAY = 0x59414b4f, A_CLSE = 0x45534c43, A_WRTE = 0x45545257;
  const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  const u32 = n => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
  const q = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
  const join = (dir, name) => String(dir).replace(/\/+$/, '') + '/' + String(name).replace(/^\/+/, '');

  // ---------- RSA / ADB key handling ----------
  const b64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(s + '='.repeat((4 - s.length % 4) % 4)); return Uint8Array.from(bin, c => c.charCodeAt(0)); };
  const toBig = u => { let r = 0n; for (const b of u) r = (r << 8n) | BigInt(b); return r; };
  const toLE = (n, len) => { const o = new Uint8Array(len); for (let i = 0; i < len; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
  const modPow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };

  async function getKey() {
    let jwk;
    try { jwk = JSON.parse(localStorage.getItem('webadb-key')); } catch (e) {}
    if (!jwk) {
      const k = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign']);
      jwk = await crypto.subtle.exportKey('jwk', k.privateKey);
      try { localStorage.setItem('webadb-key', JSON.stringify(jwk)); } catch (e) {}
    }
    const n = toBig(b64u(jwk.n)), d = toBig(b64u(jwk.d));
    return { n, d };
  }
  // ADB signs the raw 20-byte token as if it were a SHA-1 digest (PKCS#1 v1.5)
  const SHA1_PREFIX = Uint8Array.from([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]);
  function signToken(key, token) {
    const pad = 256 - 3 - SHA1_PREFIX.length - token.length;
    const em = cat(Uint8Array.from([0, 1]), new Uint8Array(pad).fill(0xff), Uint8Array.from([0]), SHA1_PREFIX, token);
    let x = modPow(toBig(em), key.d, key.n);
    const o = new Uint8Array(256);
    for (let i = 255; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; }
    return o; // big-endian signature
  }
  function publicKeyBlob(key) {
    const n = key.n;
    let x = 1n; const M = 1n << 32n;
    for (let i = 0; i < 6; i++) x = x * (2n - n * x) % M;       // n^-1 mod 2^32
    const n0inv = (M - x) % M;
    const rr = modPow(2n, 4096n, n);
    const st = cat(u32(64), u32(Number(n0inv)), toLE(n, 256), toLE(rr, 256), u32(65537));
    return enc.encode(btoa(String.fromCharCode(...st)) + ' turbowarp@webadb\0');
  }

  // ---------- ADB transport ----------
  class Stream {
    constructor(conn, id) {
      this.conn = conn; this.id = id; this.rb = new Uint8Array(0); this.closed = false; this.remoteId = 0;
      this.opened = new Promise((res, rej) => { this._res = res; this._rej = rej; });
    }
    _ack(remote) { if (!this.remoteId) { this.remoteId = remote; this._res(); } else if (this.ackWait) { const f = this.ackWait; this.ackWait = null; f(); } }
    _data(d) { this.rb = cat(this.rb, d); this._wake(); }
    _wake() { const w = this.waiter; this.waiter = null; if (w) w(); }
    _close() {
      this.closed = true;
      if (!this.remoteId) this._rej(new Error('Device refused service'));
      if (this.ackWait) { this.ackWait(); this.ackWait = null; }
      this._wake();
    }
    async write(data) {
      for (let i = 0; i < data.length || i === 0; i += this.conn.maxData) {
        if (this.closed) throw new Error('Stream closed');
        this.conn._send(A_WRTE, this.id, this.remoteId, data.subarray(i, i + this.conn.maxData));
        await new Promise(r => { this.ackWait = r; });
        if (data.length === 0) break;
      }
    }
    async read(n) {
      while (this.rb.length < n) {
        if (this.closed) throw new Error('Stream closed');
        await new Promise(r => { this.waiter = r; });
      }
      const out = this.rb.slice(0, n); this.rb = this.rb.slice(n); return out;
    }
    async readAll() { while (!this.closed) await new Promise(r => { this.waiter = r; }); return this.rb; }
    close() { if (!this.closed) { this.conn._send(A_CLSE, this.id, this.remoteId); this.closed = true; this.conn.streams.delete(this.id); } }
  }

  class Conn {
    constructor() { this.buf = new Uint8Array(0); this.streams = new Map(); this.nextId = 1; this.maxData = 4096; this.signed = false; this.closed = false; }
    open(url) {
      return new Promise((res, rej) => {
        const t = setTimeout(() => { rej(new Error('Timed out. Is the bridge running and the headset authorized?')); this.close(); }, 20000);
        this._ready = () => { clearTimeout(t); res(); };
        let ws;
        try { ws = this.ws = new WebSocket(url); } catch (e) { clearTimeout(t); return rej(e); }
        ws.binaryType = 'arraybuffer';
        ws.onerror = () => { clearTimeout(t); rej(new Error('Could not reach the WebSocket bridge')); };
        ws.onclose = () => { this.closed = true; for (const s of this.streams.values()) s._close(); this.streams.clear(); };
        ws.onmessage = e => this._feed(new Uint8Array(e.data));
        ws.onopen = () => this._send(A_CNXN, 0x01000001, 256 * 1024, enc.encode('host::\0'));
      });
    }
    close() { try { this.ws.close(); } catch (e) {} }
    _send(cmd, a0, a1, data = new Uint8Array(0)) {
      const h = new Uint8Array(24), v = new DataView(h.buffer);
      v.setUint32(0, cmd, true); v.setUint32(4, a0 >>> 0, true); v.setUint32(8, a1 >>> 0, true);
      v.setUint32(12, data.length, true); v.setUint32(16, 0, true); v.setUint32(20, (cmd ^ 0xffffffff) >>> 0, true);
      this.ws.send(cat(h, data));
    }
    _feed(d) {
      this.buf = cat(this.buf, d);
      while (this.buf.length >= 24) {
        const v = new DataView(this.buf.buffer, this.buf.byteOffset);
        const len = v.getUint32(12, true);
        if (this.buf.length < 24 + len) break;
        const cmd = v.getUint32(0, true), a0 = v.getUint32(4, true), a1 = v.getUint32(8, true);
        const data = this.buf.slice(24, 24 + len);
        this.buf = this.buf.slice(24 + len);
        this._handle(cmd, a0, a1, data);
      }
    }
    async _handle(cmd, a0, a1, data) {
      try {
        if (cmd === A_CNXN) { this.maxData = Math.min(a1, 65536) || 4096; this._ready(); }
        else if (cmd === A_AUTH && a0 === 1) {
          const key = await getKey();
          if (!this.signed) { this.signed = true; this._send(A_AUTH, 2, 0, signToken(key, data)); }
          else this._send(A_AUTH, 3, 0, publicKeyBlob(key)); // headset will show "Allow USB debugging?"
        } else if (cmd === A_OKAY) { const s = this.streams.get(a1); if (s) s._ack(a0); }
        else if (cmd === A_WRTE) { const s = this.streams.get(a1); if (s) { s._data(data); this._send(A_OKAY, a1, a0); } }
        else if (cmd === A_CLSE) { const s = this.streams.get(a1); if (s) { s._close(); this.streams.delete(a1); } }
      } catch (e) { console.error('[WebADB]', e); }
    }
    async openStream(service) {
      const id = this.nextId++, s = new Stream(this, id);
      this.streams.set(id, s);
      this._send(A_OPEN, id, 0, enc.encode(service + '\0'));
      await s.opened;
      return s;
    }
    async shell(cmd) {
      const s = await this.openStream('shell:' + cmd);
      const out = dec.decode(await s.readAll());
      return out.replace(/\r\n/g, '\n').replace(/\n$/, '');
    }
    async pull(path) {
      const s = await this.openStream('sync:');
      const p = enc.encode(path);
      await s.write(cat(enc.encode('RECV'), u32(p.length), p));
      const parts = [];
      for (;;) {
        const h = await s.read(8), id = dec.decode(h.slice(0, 4)), len = new DataView(h.buffer).getUint32(4, true);
        if (id === 'DATA') parts.push(await s.read(len));
        else if (id === 'DONE') break;
        else if (id === 'FAIL') throw new Error(dec.decode(await s.read(len)));
        else throw new Error('Bad sync reply');
      }
      s.close();
      return cat(...parts);
    }
    async push(path, bytes) {
      const s = await this.openStream('sync:');
      const p = enc.encode(path + ',33206');
      await s.write(cat(enc.encode('SEND'), u32(p.length), p));
      for (let i = 0; i < bytes.length; i += 65536) {
        const c = bytes.subarray(i, i + 65536);
        await s.write(cat(enc.encode('DATA'), u32(c.length), c));
      }
      await s.write(cat(enc.encode('DONE'), u32(Math.floor(Date.now() / 1000))));
      const h = await s.read(8), id = dec.decode(h.slice(0, 4)), len = new DataView(h.buffer).getUint32(4, true);
      if (id === 'FAIL') throw new Error(dec.decode(await s.read(len)));
      s.close();
    }
  }

  // ---------- Extension ----------
  class WebADB {
    constructor() { this.ip = ''; this.port = ''; this.bridge = 'ws://127.0.0.1:8765'; this.conn = null; this.err = ''; this.apkFile = null; }
    getInfo() {
      return {
        id: 'karbonadb', name: 'KarbonADB', color1: '#2e8b57', color2: '#246b43',
        blocks: [
          { opcode: 'connect', blockType: Scratch.BlockType.COMMAND, text: 'connect to headset' },
          { opcode: 'disconnect', blockType: Scratch.BlockType.COMMAND, text: 'disconnect headset' },
          { opcode: 'connected', blockType: Scratch.BlockType.BOOLEAN, text: 'connected?' },
          { opcode: 'lastError', blockType: Scratch.BlockType.REPORTER, text: 'last error' },
          '---',
          { opcode: 'setIp', blockType: Scratch.BlockType.COMMAND, text: 'set IP to [IP]', arguments: { IP: { type: Scratch.ArgumentType.STRING, defaultValue: '192.168.1.50' } } },
          { opcode: 'setPort', blockType: Scratch.BlockType.COMMAND, text: 'set port to [PORT]', arguments: { PORT: { type: Scratch.ArgumentType.STRING, defaultValue: '5555' } } },
          { opcode: 'setBridge', blockType: Scratch.BlockType.COMMAND, text: 'set bridge URL to [URL]', arguments: { URL: { type: Scratch.ArgumentType.STRING, defaultValue: 'ws://127.0.0.1:8765' } } },
          '---',
          { opcode: 'run', blockType: Scratch.BlockType.REPORTER, text: 'run ADB command [CMD]', arguments: { CMD: { type: Scratch.ArgumentType.STRING, defaultValue: 'shell ls /sdcard' } } },
          { opcode: 'mkdir', blockType: Scratch.BlockType.COMMAND, text: 'create folder [NAME] in [PATH]', arguments: { NAME: { type: Scratch.ArgumentType.STRING, defaultValue: 'MyNEWFolder' }, PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/' } } },
          { opcode: 'touch', blockType: Scratch.BlockType.COMMAND, text: 'create file [NAME] in [PATH]', arguments: { NAME: { type: Scratch.ArgumentType.STRING, defaultValue: 'file.txt' }, PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/' } } },
          { opcode: 'write', blockType: Scratch.BlockType.COMMAND, text: 'write [DATA] to file [PATH]', arguments: { DATA: { type: Scratch.ArgumentType.STRING, defaultValue: 'hello' }, PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/file.txt' } } },
          { opcode: 'rmFile', blockType: Scratch.BlockType.COMMAND, text: 'remove file [NAME] in [PATH]', arguments: { NAME: { type: Scratch.ArgumentType.STRING, defaultValue: 'file.txt' }, PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/' } } },
          { opcode: 'rmFolderPath', blockType: Scratch.BlockType.COMMAND, text: 'remove folder [PATH]', arguments: { PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/MyNEWFolder/' } } },
          { opcode: 'rmFolder', blockType: Scratch.BlockType.COMMAND, text: 'remove folder [NAME] in [PATH]', arguments: { NAME: { type: Scratch.ArgumentType.STRING, defaultValue: 'MyNEWFolder' }, PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/' } } },
          { opcode: 'read', blockType: Scratch.BlockType.REPORTER, text: 'read file [PATH]', arguments: { PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/file.txt' } } },
          { opcode: 'download', blockType: Scratch.BlockType.COMMAND, text: 'download file [PATH]', arguments: { PATH: { type: Scratch.ArgumentType.STRING, defaultValue: '/sdcard/file.txt' } } },
          '---',
          { opcode: 'chooseApk', blockType: Scratch.BlockType.COMMAND, text: 'choose APK file from computer' },
          { opcode: 'installPerm', blockType: Scratch.BlockType.COMMAND, text: 'install APK [APK] with [PERMS] permissions', arguments: { APK: { type: Scratch.ArgumentType.STRING, defaultValue: '' }, PERMS: { type: Scratch.ArgumentType.STRING, menu: 'perms', defaultValue: 'all' } } },
          { opcode: 'install', blockType: Scratch.BlockType.COMMAND, text: 'install APK [APK]', arguments: { APK: { type: Scratch.ArgumentType.STRING, defaultValue: '' } } },
          '---',
          { opcode: 'setProp', blockType: Scratch.BlockType.COMMAND, text: 'set property [PROP] to [VALUE]', arguments: { PROP: { type: Scratch.ArgumentType.STRING, defaultValue: 'debug.oculus.foveation' }, VALUE: { type: Scratch.ArgumentType.STRING, defaultValue: '1' } } },
          { opcode: 'getProp', blockType: Scratch.BlockType.REPORTER, text: 'get property [PROP]', arguments: { PROP: { type: Scratch.ArgumentType.STRING, defaultValue: 'ro.product.model' } } }
        ],
        menus: { perms: { acceptReporters: false, items: ['all', 'none'] } }
      };
    }
    async _g(fn) { // run + capture errors
      this.err = '';
      try { return await fn(); } catch (e) { this.err = String(e && e.message || e); return ''; }
    }
    _need() { if (!this.conn || this.conn.closed) throw new Error('Not connected'); return this.conn; }

    connect() {
      return this._g(async () => {
        if (!this.ip) throw new Error('Set IP first');
        if (this.conn) this.conn.close();
        const port = String(this.port).trim() || '5555';
        const c = new Conn();
        await c.open(`${this.bridge}/?host=${encodeURIComponent(this.ip)}&port=${encodeURIComponent(port)}`);
        this.conn = c;
      });
    }
    disconnect() { if (this.conn) this.conn.close(); this.conn = null; }
    connected() { return !!(this.conn && !this.conn.closed); }
    lastError() { return this.err; }
    setIp(a) { this.ip = String(a.IP).trim(); }
    setPort(a) { this.port = String(a.PORT).trim(); }
    setBridge(a) { this.bridge = String(a.URL).trim().replace(/\/+$/, ''); }

    run(a) {
      return this._g(() => {
        let c = String(a.CMD).trim().replace(/^adb\s+/, '');
        if (/^(pull|push|install|connect|pair|disconnect)\b/.test(c)) throw new Error('Use the dedicated blocks for that command');
        c = c.replace(/^shell\s+/, '');
        return this._need().shell(c);
      });
    }
    mkdir(a) { return this._g(() => this._need().shell('mkdir -p ' + q(join(a.PATH, a.NAME)))); }
    touch(a) { return this._g(() => this._need().shell('touch ' + q(join(a.PATH, a.NAME)))); }
    write(a) { return this._g(() => this._need().push(String(a.PATH), enc.encode(String(a.DATA)))); } // sync push: no shell-quoting problems
    rmFile(a) { return this._g(() => this._need().shell('rm -f ' + q(join(a.PATH, a.NAME)))); }
    rmFolderPath(a) { return this._g(() => this._need().shell('rm -rf ' + q(a.PATH))); }
    rmFolder(a) { return this._g(() => this._need().shell('rm -rf ' + q(join(a.PATH, a.NAME)))); }
    read(a) { return this._g(() => this._need().shell('cat ' + q(a.PATH))); }
    download(a) {
      return this._g(async () => {
        const bytes = await this._need().pull(String(a.PATH));
        const url = URL.createObjectURL(new Blob([bytes]));
        const el = document.createElement('a');
        el.href = url; el.download = String(a.PATH).split('/').filter(Boolean).pop() || 'download';
        document.body.appendChild(el); el.click(); el.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
      });
    }

    chooseApk() {
      return new Promise(res => {
        const i = document.createElement('input'); i.type = 'file'; i.accept = '.apk';
        i.onchange = () => { this.apkFile = i.files[0] || null; res(); };
        i.oncancel = () => res();
        i.click();
      });
    }
    async _apkBytes(src) {
      src = String(src).trim();
      if (!src) { if (!this.apkFile) throw new Error('No APK chosen'); return new Uint8Array(await this.apkFile.arrayBuffer()); }
      const r = await fetch(src); if (!r.ok) throw new Error('APK download failed: ' + r.status);
      return new Uint8Array(await r.arrayBuffer());
    }
    _install(apk, grant) {
      return this._g(async () => {
        const c = this._need(), tmp = '/data/local/tmp/_webadb_install.apk';
        await c.push(tmp, await this._apkBytes(apk));
        const out = await c.shell(`pm install ${grant ? '-g ' : ''}${tmp}`);
        await c.shell('rm -f ' + tmp);
        if (!/Success/i.test(out)) throw new Error(out || 'Install failed');
      });
    }
    installPerm(a) { return this._install(a.APK, a.PERMS === 'all'); }
    install(a) { return this._install(a.APK, false); }

    setProp(a) { return this._g(() => this._need().shell(`setprop ${q(a.PROP)} ${q(a.VALUE)}`)); }
    getProp(a) { return this._g(() => this._need().shell('getprop ' + q(a.PROP))); }
  }

  Scratch.extensions.register(new WebADB());
})(Scratch);
