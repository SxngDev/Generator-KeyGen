import { pool } from './db.js';
import { addDays, generateKey } from './utils.js';
import { notifyAll } from './notifications.js';
export async function createKeyAfterPayment({ buyerEmail, productId, planDays=30, deviceLimit=1, prefix='KEY', ownerId=null }){
  const code = generateKey({ prefix });
  const expiresAt = planDays>0 ? addDays(new Date(), planDays) : null;
  const { rows } = await pool.query(
    `INSERT INTO license_keys (code, plan, days, prefix, owner_id, expires_at, product_id, device_limit)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [code, planDays===0?'permanent':`${planDays}d`, planDays, prefix, ownerId, expiresAt, productId, deviceLimit]
  );
  await notifyAll(`✅ Pago confirmado → Key generada: ${rows[0].code} (producto ${productId})`);
  return rows[0];
}
export async function handleStripeEvent(type, data){
  if(type==='checkout.session.completed'){
    const md = data?.metadata || {};
    return await createKeyAfterPayment({
      productId: md.product_id, planDays: parseInt(md.plan_days||'30',10),
      prefix: md.prefix || 'KEY', ownerId: md.owner_id || null
    });
  } return null;
}
export async function handlePayPalEvent(event){
  const md = event?.resource?.custom_id ? JSON.parse(event.resource.custom_id) : {};
  return await createKeyAfterPayment({
    productId: md.product_id, planDays: parseInt(md.plan_days||'30',10),
    prefix: md.prefix || 'KEY', ownerId: md.owner_id || null
  });
}
