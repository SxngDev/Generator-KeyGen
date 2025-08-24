import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import fs from 'fs';
import speakeasy from 'speakeasy';
import { pool } from './db.js';
import { sign, auth, requireRole, hashPassword, comparePassword, hasRoleOrAbove } from './auth.js';
import { generateKey, addDays, remainingSeconds } from './utils.js';
import { overviewStats, activityByDay } from './stats.js';
import { handleStripeEvent, handlePayPalEvent } from './payments.js';
import { notifyAll } from './notifications.js';

dotenv.config();
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(helmet());
app.use(morgan('tiny'));
app.use(cors({ origin: process.env.ALLOW_ORIGIN ? [process.env.ALLOW_ORIGIN] : true }));
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 100 });
app.use('/api/', apiLimiter);

// Schema init
const schema = fs.readFileSync(new URL('./schema.sql', import.meta.url));
await pool.query(schema.toString());

// Bootstrap owner
async function bootstrap(){
  const email = process.env.ADMIN_EMAIL, password = process.env.ADMIN_PASSWORD || 'owner123';
  if(!email) return;
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  if(rows.length===0){
    const pass = await hashPassword(password);
    const username = email.split('@')[0];
    await pool.query('INSERT INTO users (username,email,password_hash,role) VALUES ($1,$2,$3,$4)', [username,email,pass,'owner']);
    await pool.query('INSERT INTO user_limits (user_id,daily_key_quota) SELECT id,1000 FROM users WHERE email=$1', [email]);
    console.log('Owner creado:', email);
  } else if(rows[0].role!=='owner'){ await pool.query('UPDATE users SET role=$1 WHERE email=$2',['owner',email]); }
}
await bootstrap();

// Health
app.get('/api/health', (req,res)=> res.json({ok:true}));

// Captcha helper
async function verifyCaptcha(token){
  const secret = process.env.RECAPTCHA_SECRET;
  if(!secret) return true;
  try{
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify',{
      method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body: new URLSearchParams({ secret, response: token })
    }); const j = await r.json(); return !!j.success;
  }catch{ return false; }
}

// Auth
app.post('/api/auth/register', async (req,res)=>{
  const { username,email,whatsapp,country,password } = req.body||{};
  if(!username||!email||!password) return res.status(400).json({error:'Campos requeridos'});
  const ex = await pool.query('SELECT 1 FROM users WHERE email=$1 OR username=$2',[email,username]);
  if(ex.rowCount>0) return res.status(409).json({error:'Usuario o email ya existen'});
  const hash = await hashPassword(password);
  const { rows } = await pool.query('INSERT INTO users (username,email,whatsapp,country,password_hash,role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',[username,email,whatsapp||null,country||null,hash,'user']);
  await pool.query('INSERT INTO user_limits (user_id) VALUES ($1) ON CONFLICT DO NOTHING',[rows[0].id]);
  res.json({ token: sign(rows[0]) });
});

app.post('/api/auth/login', async (req,res)=>{
  const { email, password, otp } = req.body||{};
  if(!email||!password) return res.status(400).json({error:'Campos requeridos'});
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1',[email]);
  if(rows.length===0) return res.status(401).json({error:'Credenciales inválidas'});
  const ok = await comparePassword(password, rows[0].password_hash);
  if(!ok) return res.status(401).json({error:'Credenciales inválidas'});
  if(rows[0].two_factor_enabled){
    const verified = speakeasy.totp.verify({ secret: rows[0].two_factor_secret||'', encoding:'base32', token: otp||'', window:1 });
    if(!verified) return res.status(401).json({error:'OTP inválido o requerido'});
  }
  await pool.query('INSERT INTO audit_logs (actor_id,action) VALUES ($1,$2)', [rows[0].id,'LOGIN']);
  await notifyAll(`🔐 Login: ${rows[0].email}`);
  res.json({ token: sign(rows[0]) });
});

app.post('/api/auth/2fa/setup', auth(true), async (req,res)=>{
  const secret = speakeasy.generateSecret({ name: 'KeyGenStore (' + req.user.email + ')' });
  await pool.query('UPDATE users SET two_factor_secret=$1, two_factor_enabled=FALSE WHERE id=$2', [secret.base32, req.user.id]);
  res.json({ otpauth_url: secret.otpauth_url, base32: secret.base32 });
});
app.post('/api/auth/2fa/verify', auth(true), async (req,res)=>{
  const { otp } = req.body||{}; if(!otp) return res.status(400).json({error:'otp requerido'});
  const { rows } = await pool.query('SELECT two_factor_secret FROM users WHERE id=$1',[req.user.id]);
  const verified = speakeasy.totp.verify({ secret: rows[0]?.two_factor_secret||'', encoding:'base32', token: otp, window:1 });
  if(!verified) return res.status(401).json({error:'OTP inválido'});
  await pool.query('UPDATE users SET two_factor_enabled=TRUE WHERE id=$1',[req.user.id]);
  res.json({ ok:true });
});

// OAuth stubs
app.get('/api/oauth/google/start', (req,res)=> res.status(501).json({error:'Google OAuth no configurado'}));
app.get('/api/oauth/discord/start', (req,res)=> res.status(501).json({error:'Discord OAuth no configurado'}));
app.get('/api/oauth/google/callback', (req,res)=> res.status(501).json({error:'Callback Google no configurado'}));
app.get('/api/oauth/discord/callback', (req,res)=> res.status(501).json({error:'Callback Discord no configurado'}));

// Users
app.get('/api/users', auth(true), requireRole('admin'), async (req,res)=>{
  const { rows } = await pool.query('SELECT u.id,u.username,u.email,u.role,u.created_at, COALESCE(ul.daily_key_quota,100) AS daily_key_quota FROM users u LEFT JOIN user_limits ul ON ul.user_id=u.id ORDER BY u.created_at DESC LIMIT 500');
  res.json(rows);
});
app.post('/api/users', auth(true), requireRole('admin'), async (req,res)=>{
  const { username,email,password,role='reseller',daily_key_quota=200 } = req.body||{};
  if(!username||!email||!password) return res.status(400).json({error:'Campos requeridos'});
  if(role==='admin' && req.user.role!=='owner') return res.status(403).json({error:'Solo owner puede crear admin'});
  const ex = await pool.query('SELECT 1 FROM users WHERE email=$1 OR username=$2',[email,username]);
  if(ex.rowCount>0) return res.status(409).json({error:'Usuario o email ya existen'});
  const hash = await hashPassword(password);
  const { rows } = await pool.query('INSERT INTO users (username,email,password_hash,role) VALUES ($1,$2,$3,$4) RETURNING id,username,email,role,created_at',[username,email,hash,role]);
  await pool.query('INSERT INTO user_limits (user_id,daily_key_quota) VALUES ($1,$2) ON CONFLICT (user_id) DO UPDATE SET daily_key_quota=EXCLUDED.daily_key_quota',[rows[0].id,daily_key_quota]);
  await pool.query('INSERT INTO audit_logs (actor_id,action,meta) VALUES ($1,$2,$3)', [req.user.id,'CREATE_USER', {user_id: rows[0].id, role, daily_key_quota}]);
  res.json(rows[0]);
});
app.patch('/api/users/:id', auth(true), requireRole('admin'), async (req,res)=>{
  const { id } = req.params; const { role, password, daily_key_quota } = req.body||{};
  if(role){ if(req.user.role!=='owner') return res.status(403).json({error:'Solo owner puede cambiar roles'}); if(!['user','reseller','admin'].includes(role)) return res.status(400).json({error:'Rol inválido'}); await pool.query('UPDATE users SET role=$1 WHERE id=$2',[role,id]); }
  if(password){ const h = await hashPassword(password); await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2',[h,id]); }
  if(typeof daily_key_quota==='number'){ await pool.query('INSERT INTO user_limits (user_id,daily_key_quota) VALUES ($1,$2) ON CONFLICT (user_id) DO UPDATE SET daily_key_quota=EXCLUDED.daily_key_quota',[id,daily_key_quota]); }
  await pool.query('INSERT INTO audit_logs (actor_id,action,meta) VALUES ($1,$2,$3)', [req.user.id,'UPDATE_USER',{id,role:role||null, daily_key_quota:daily_key_quota||null}]);
  res.json({ ok:true });
});

async function checkQuota(userId, addCount){
  const q = await pool.query('SELECT COALESCE((SELECT daily_key_quota FROM user_limits WHERE user_id=$1),100) AS quota',[userId]);
  const quota = q.rows[0].quota;
  const used = (await pool.query(`SELECT COUNT(*)::int AS used FROM audit_logs WHERE actor_id=$1 AND action='GENERATE' AND created_at::date = now()::date`,[userId])).rows[0].used;
  return { ok: used+addCount<=quota, quota, used };
}

// Products
app.post('/api/products', auth(true), requireRole('admin'), async (req,res)=>{
  const { name,slug,description,allowed_countries } = req.body||{};
  if(!name||!slug) return res.status(400).json({error:'name y slug requeridos'});
  const { rows } = await pool.query('INSERT INTO products (name,slug,description,allowed_countries) VALUES ($1,$2,$3,$4) RETURNING *',[name,slug,description||null,allowed_countries||null]);
  res.json(rows[0]);
});
app.get('/api/products', async (req,res)=>{
  const { rows } = await pool.query('SELECT id,name,slug,description FROM products WHERE active=TRUE ORDER BY created_at DESC LIMIT 100');
  res.json(rows);
});

// Variables y mensajes
app.put('/api/variables', auth(true), requireRole('admin'), async (req,res)=>{
  const { product_id,name,value,protected:prot=false } = req.body||{};
  if(!product_id||!name) return res.status(400).json({error:'product_id y name requeridos'});
  const { rows } = await pool.query(`INSERT INTO app_variables (product_id,name,value,protected) VALUES ($1,$2,$3,$4)
    ON CONFLICT (product_id,name) DO UPDATE SET value=excluded.value, protected=excluded.protected, updated_at=now() RETURNING *`,[product_id,name,value||'',prot]);
  res.json(rows[0]);
});
app.put('/api/messages', auth(true), requireRole('admin'), async (req,res)=>{
  const { product_id,content,active=true } = req.body||{};
  if(!product_id||!content) return res.status(400).json({error:'product_id y content requeridos'});
  const { rows } = await pool.query('INSERT INTO global_messages (product_id,content,active) VALUES ($1,$2,$3) RETURNING *',[product_id,content,active]);
  res.json(rows[0]);
});

// Keys
app.post('/api/keys/generate', auth(true), requireRole('reseller'), async (req,res)=>{
  const { quantity=1, days=30, plan='30d', prefix='KEY', groups=4, groupLen=5, note, product_id, device_limit=1, max_validations } = req.body||{};
  if(quantity<1 || quantity>1000) return res.status(400).json({error:'quantity 1-1000'});
  const quota = await checkQuota(req.user.id, quantity);
  if(!quota.ok) return res.status(429).json({error:`Excede cuota diaria (${quota.used}/${quota.quota})`});
  const owner_id = req.user.id; const expiresAt = days>0 ? addDays(new Date(), days) : null;
  const results = []; await pool.query('BEGIN');
  try{
    for(let i=0;i<quantity;i++){
      const code = generateKey({groups, groupLen, prefix});
      const { rows } = await pool.query(
        `INSERT INTO license_keys (code,plan,days,prefix,note,owner_id,expires_at,product_id,device_limit,max_validations)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [code, plan, days, prefix, note||null, owner_id, expiresAt, product_id||null, device_limit||1, max_validations||null]
      ); results.push(rows[0]);
    }
    await pool.query('COMMIT');
    await pool.query('INSERT INTO audit_logs (actor_id,action,meta) VALUES ($1,$2,$3)', [req.user.id,'GENERATE',{count:results.length}]);
    res.json({ ok:true, count:results.length, keys: results.map(k=>k.code) });
  }catch(e){ await pool.query('ROLLBACK'); console.error(e); res.status(500).json({error:'No se pudieron generar las keys'}); }
});
app.get('/api/keys', auth(true), async (req,res)=>{
  const { q,status } = req.query; let sql='SELECT * FROM license_keys'; const params=[]; const where=[];
  if(!hasRoleOrAbove(req.user.role,'admin')){ params.push(req.user.id); where.push(`owner_id = $${params.length}`); }
  if(q){ params.push(`%${q}%`); where.push(`code ILIKE $${params.length}`); }
  if(status==='revoked') where.push('revoked_at IS NOT NULL');
  if(status==='active') where.push('revoked_at IS NULL');
  if(where.length) sql += ' WHERE ' + where.join(' AND '); sql += ' ORDER BY created_at DESC LIMIT 200';
  const { rows } = await pool.query(sql, params); res.json(rows);
});
app.post('/api/keys/revoke', auth(true), async (req,res)=>{
  const { code } = req.body||{}; if(!code) return res.status(400).json({error:'code requerido'});
  const { rows } = await pool.query('SELECT * FROM license_keys WHERE code=$1',[code]);
  if(!rows.length) return res.status(404).json({error:'Key no encontrada'});
  const key = rows[0]; if(!hasRoleOrAbove(req.user.role,'admin') && key.owner_id!==req.user.id) return res.status(403).json({error:'Forbidden'});
  await pool.query('UPDATE license_keys SET revoked_at=now() WHERE id=$1',[key.id]);
  await pool.query('INSERT INTO audit_logs (actor_id,action,meta) VALUES ($1,$2,$3)', [req.user.id,'REVOKE',{code}]);
  res.json({ ok:true });
});
app.post('/api/keys/unbind', auth(true), async (req,res)=>{
  const { code } = req.body||{}; if(!code) return res.status(400).json({error:'code requerido'});
  const { rows } = await pool.query('SELECT * FROM license_keys WHERE code=$1',[code]);
  if(!rows.length) return res.status(404).json({error:'Key no encontrada'});
  const key = rows[0]; if(!hasRoleOrAbove(req.user.role,'admin') && key.owner_id!==req.user.id) return res.status(403).json({error:'Forbidden'});
  await pool.query('UPDATE license_keys SET hwid=NULL, used_at=NULL WHERE id=$1',[key.id]);
  await pool.query('DELETE FROM license_devices WHERE key_id=$1',[key.id]);
  res.json({ ok:true });
});

// Validate (pública)
app.post('/api/keys/validate', async (req,res)=>{
  const { code, hwid, client_note } = req.body||{};
  if(!code||!hwid) return res.status(400).json({error:'code y hwid requeridos'});
  const { rows } = await pool.query('SELECT * FROM license_keys WHERE code=$1',[code]);
  if(rows.length===0) return res.status(404).json({ valid:false, reason:'not_found' });
  const key = rows[0];
  if(key.revoked_at) return res.status(403).json({ valid:false, reason:'revoked' });
  if(key.expires_at && new Date(key.expires_at).getTime()<Date.now()) return res.status(403).json({ valid:false, reason:'expired' });
  if(!key.hwid){ await pool.query('UPDATE license_keys SET hwid=$1, used_at=now() WHERE id=$2',[hwid,key.id]); }
  else if(key.hwid!==hwid) return res.status(403).json({ valid:false, reason:'hwid_mismatch' });
  await pool.query('INSERT INTO redemptions (key_id,hwid,client_note) VALUES ($1,$2,$3)', [key.id, hwid, client_note||null]);
  res.json({ valid:true, code:key.code, plan:key.plan, expires_at:key.expires_at, seconds_remaining: remainingSeconds(key.expires_at), hwid:key.hwid||hwid });
});

// Client API (KeyAuth-like minimal)
app.post('/api/client/authorize', async (req,res)=>{
  const { key, hwid, product_id, captcha_token, country } = req.body||{};
  if(!(await verifyCaptcha(captcha_token||''))) return res.status(400).json({error:'Captcha inválido'});
  if(!key||!hwid||!product_id) return res.status(400).json({error:'key, hwid, product_id requeridos'});
  const kr = await pool.query('SELECT * FROM license_keys WHERE code=$1 AND product_id=$2',[key,product_id]);
  if(kr.rowCount===0) return res.status(404).json({ ok:false, reason:'not_found' });
  const K = kr.rows[0];
  if(K.revoked_at) return res.status(403).json({ ok:false, reason:'revoked' });
  if(K.expires_at && new Date(K.expires_at).getTime()<Date.now()) return res.status(403).json({ ok:false, reason:'expired' });
  const pr = await pool.query('SELECT * FROM products WHERE id=$1 AND active=TRUE',[product_id]);
  if(pr.rowCount===0) return res.status(404).json({ ok:false, reason:'product_inactive' });
  const P = pr.rows[0];
  if(P.allowed_countries && country){ try { if(Array.isArray(P.allowed_countries) && P.allowed_countries.length && !P.allowed_countries.includes(country.toUpperCase())) return res.status(403).json({ ok:false, reason:'geo_blocked' }); }catch{}}  
  const devCount = (await pool.query('SELECT COUNT(*)::int AS c FROM license_devices WHERE key_id=$1',[K.id])).rows[0].c;
  const hasDev = (await pool.query('SELECT 1 FROM license_devices WHERE key_id=$1 AND hwid=$2',[K.id,hwid])).rowCount>0;
  if(!hasDev){
    if(devCount >= (K.device_limit||1)) return res.status(403).json({ ok:false, reason:'device_limit_reached' });
    await pool.query('INSERT INTO license_devices (key_id,hwid) VALUES ($1,$2) ON CONFLICT DO NOTHING',[K.id, hwid]);
  }
  if(K.max_validations && K.validations_used >= K.max_validations) return res.status(403).json({ ok:false, reason:'validation_limit_reached' });
  await pool.query('UPDATE license_keys SET validations_used=COALESCE(validations_used,0)+1 WHERE id=$1',[K.id]);
  await pool.query('INSERT INTO redemptions (key_id,hwid,client_note) VALUES ($1,$2,$3)', [K.id, hwid, 'client_auth']);
  const vars = await pool.query('SELECT name,value FROM app_variables WHERE product_id=$1',[product_id]);
  const msg  = await pool.query('SELECT content FROM global_messages WHERE product_id=$1 AND active=TRUE ORDER BY created_at DESC LIMIT 1',[product_id]);
  res.json({ ok:true, key:K.code, plan:K.plan, expires_at:K.expires_at, seconds_remaining: remainingSeconds(K.expires_at), variables: vars.rows, message: msg.rows[0]?.content || null });
});

// Stats
app.get('/api/stats/overview', auth(true), async (req,res)=> res.json(await overviewStats(req.user)));
app.get('/api/stats/activity', auth(true), async (req,res)=>{ const days=parseInt(req.query.days||'30',10); res.json(await activityByDay(req.user, days)); });

// Payments webhooks (stubs)
app.post('/api/payments/stripe/webhook', express.raw({type:'application/json'}), async (req,res)=>{
  try{ const event = JSON.parse(req.body.toString('utf8')); await handleStripeEvent(event.type, event.data.object); res.json({received:true}); }
  catch(e){ res.status(400).json({error:'invalid payload'}); }
});
app.post('/api/payments/paypal/webhook', async (req,res)=>{ try{ await handlePayPalEvent(req.body); res.json({received:true}); } catch(e){ res.status(400).json({error:'invalid payload'}); } });

const port = process.env.PORT || 8080;
app.listen(port, ()=> console.log('API en puerto', port));
