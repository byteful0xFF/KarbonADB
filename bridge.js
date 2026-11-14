// Run: npm i ws && node bridge.js
// Forwards ws://127.0.0.1:8765/?host=<ip>&port=<port> to the headset's ADB TCP port.
const { WebSocketServer } = require('ws');
const net = require('net');

new WebSocketServer({ host: '127.0.0.1', port: 8765 }).on('connection', (ws, req) => {
  const u = new URL(req.url, 'http://localhost');
  const host = u.searchParams.get('host'), port = Number(u.searchParams.get('port') || 5555);
  const s = net.connect(port, host);
  s.on('data', d => ws.send(d));
  s.on('close', () => ws.close());
  s.on('error', () => ws.close());
  ws.on('message', d => s.write(d));
  ws.on('close', () => s.destroy());
});
console.log('ADB bridge on ws://127.0.0.1:8765');
