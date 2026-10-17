// Semua endpoint web pairing dalam satu file: /api/login, /api/logout, /api/status, /api/pair.
const crypto = require('node:crypto');

const WA_API_URL = String(process.env.WA_API_URL || '').trim().replace(/\/+$/, '');
const WA_API_SECRET = String(process.env.WA_API_SECRET || '').trim();
const WEB_PASSWORD = String(process.env.WEB_PASSWORD || '');
const SESSION_KEY = process.env.SESSION_SECRET || crypto.createHash('sha256').update(`session:${WEB_PASSWORD}`).digest('hex');
const SESSION_MS = 2 * 60 * 60 * 1000;

function configOk() {
	return /^https?:\/\//.test(WA_API_URL) && WA_API_SECRET.length >= 16 && WEB_PASSWORD.length >= 12;
}

function send(res, status, body, type = 'application/json; charset=utf-8', extraHeaders = {}) {
	res.statusCode = status;
	res.setHeader('content-type', type);
	res.setHeader('cache-control', 'no-store');
	res.setHeader('x-content-type-options', 'nosniff');
	res.setHeader('referrer-policy', 'no-referrer');
	res.setHeader('x-frame-options', 'DENY');
	for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
	const isRaw = typeof body === 'string' || Buffer.isBuffer(body);
	res.end(isRaw ? body : JSON.stringify(body));
}

async function readBody(req, limit = 4096) {
	if (req.body && typeof req.body === 'object') return req.body;
	if (typeof req.body === 'string') return req.body ? JSON.parse(req.body) : {};
	const chunks = [];
	let size = 0;
	for await (const chunk of req) {
		size += chunk.length;
		if (size > limit) throw new Error('Data terlalu besar.');
		chunks.push(chunk);
	}
	const text = Buffer.concat(chunks).toString('utf8');
	try { return text ? JSON.parse(text) : {}; }
	catch { throw new Error('Format data tidak valid.'); }
}

function passwordOk(input) {
	const a = crypto.createHash('sha256').update(String(input || '')).digest();
	const b = crypto.createHash('sha256').update(WEB_PASSWORD).digest();
	return crypto.timingSafeEqual(a, b);
}

function hmacHex(data) {
	return crypto.createHmac('sha256', SESSION_KEY).update(data).digest('hex');
}

function makeSessionToken() {
	const exp = String(Date.now() + SESSION_MS);
	return `${exp}.${hmacHex(exp)}`;
}

function sessionCookie(token) {
	return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}; Secure`;
}

function clearCookie() {
	return 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Secure';
}

function isLoggedIn(req) {
	const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
	if (!m) return false;
	const [exp, sig] = decodeURIComponent(m[1]).split('.');
	if (!exp || !sig || !/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
	const given = Buffer.from(sig, 'hex');
	const expected = Buffer.from(hmacHex(exp), 'hex');
	return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

function signFor(method, pathname, bodyBuf) {
	const ts = String(Date.now());
	const bodyHash = crypto.createHash('sha256').update(bodyBuf).digest('hex');
	const sig = crypto.createHmac('sha256', WA_API_SECRET)
		.update(`${ts}\n${method}\n${pathname}\n${bodyHash}`).digest('hex');
	return { 'x-wa-ts': ts, 'x-wa-sig': sig };
}

async function callBot(method, botPath, body) {
	const bodyBuf = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
	const headers = { ...signFor(method, botPath, bodyBuf) };
	if (body !== undefined) headers['content-type'] = 'application/json';
	try {
		const res = await fetch(WA_API_URL + botPath, {
			method,
			headers,
			body: body === undefined ? undefined : bodyBuf,
			signal: AbortSignal.timeout(8000),
		});
		const text = await res.text();
		let data;
		try { data = JSON.parse(text); }
		catch { data = { error: text.slice(0, 200) || `HTTP ${res.status}` }; }
		return { status: res.status, data };
	}
	catch (err) {
		console.error('[web] bot tidak bisa dihubungi:', err.name, err.message);
		return { status: 502, data: { error: 'Bot tidak bisa dihubungi. Cek WA_API_URL dan pastikan bot sedang jalan.' } };
	}
}

async function login(req, res) {
	if (!configOk()) return send(res, 500, { error: 'Environment variable belum lengkap.' });
	try {
		const body = await readBody(req);
		if (!passwordOk(body.password)) return send(res, 401, { error: 'Password salah.' });
		return send(res, 200, { ok: true }, undefined, { 'set-cookie': sessionCookie(makeSessionToken()) });
	}
	catch (err) {
		return send(res, 400, { error: err.message });
	}
}

async function logout(req, res) {
	return send(res, 200, { ok: true }, undefined, { 'set-cookie': clearCookie() });
}

async function status(req, res) {
	if (!configOk()) return send(res, 500, { error: 'Environment variable belum lengkap.' });
	if (!isLoggedIn(req)) return send(res, 401, { error: 'Belum login.' });
	const out = await callBot('GET', '/tg-api/status');
	return send(res, out.status, out.data);
}

async function pair(req, res) {
	if (!configOk()) return send(res, 500, { error: 'Environment variable belum lengkap.' });
	if (!isLoggedIn(req)) return send(res, 401, { error: 'Belum login.' });
	try {
		const input = await readBody(req);
		const number = String(input.number || '').replace(/\D/g, '');
		if (!/^\d{10,15}$/.test(number))
			return send(res, 400, { error: 'Nomor tidak valid. Contoh: 628123456789' });
		const out = await callBot('POST', '/tg-api/pair', { number });
		return send(res, out.status, out.data);
	}
	catch (err) {
		return send(res, 400, { error: err.message });
	}
}

const ENDPOINTS = { login, logout, status, pair };
const METHODS = { login: 'POST', logout: 'POST', status: 'GET', pair: 'POST' };

module.exports = async function handler(req, res) {
	let name = '';
	try {
		name = new URL(req.url, 'http://local').pathname.replace(/^\/api\//, '').replace(/\/+$/, '');
	}
	catch { }
	if (!Object.prototype.hasOwnProperty.call(ENDPOINTS, name))
		return send(res, 404, { error: 'Tidak ditemukan.' });
	if (req.method !== METHODS[name])
		return send(res, 405, { error: 'Method tidak diizinkan.' });
	return ENDPOINTS[name](req, res);
};
