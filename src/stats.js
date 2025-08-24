import { pool } from './db.js';
import { hasRoleOrAbove } from './auth.js';
export async function overviewStats(user){
  const params = []; let whereKeys=''; let whereRedeem='';
  if(!hasRoleOrAbove(user.role,'admin')){ params.push(user.id); whereKeys='WHERE owner_id=$1'; whereRedeem='WHERE k.owner_id=$1'; }
  const keys = await pool.query(`SELECT COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE revoked_at IS NULL)::int AS activas,
    COUNT(*) FILTER (WHERE revoked_at IS NOT NULL)::int AS revocadas
    FROM license_keys ${whereKeys}`, params);
  const val = await pool.query(`SELECT COUNT(*)::int AS validaciones FROM redemptions r
    JOIN license_keys k ON k.id=r.key_id ${whereRedeem}`, params);
  return { keys: keys.rows[0], validaciones: val.rows[0].validaciones };
}
export async function activityByDay(user, days=30){
  const params=[days]; let whereGen="AND action='GENERATE'"; let whereVal='';
  if(user && user.role && user.role!=='admin' && user.role!=='owner'){ params.push(user.id); whereGen += ' AND actor_id=$2'; whereVal='AND k.owner_id=$2'; }
  const gen = await pool.query(`SELECT date_trunc('day', created_at) AS d, COUNT(*)::int AS c
    FROM audit_logs WHERE created_at >= now() - ($1 || ' days')::interval ${whereGen} GROUP BY 1 ORDER BY 1`, params);
  const val = await pool.query(`SELECT date_trunc('day', r.redeemed_at) AS d, COUNT(*)::int AS c
    FROM redemptions r JOIN license_keys k ON k.id=r.key_id
    WHERE r.redeemed_at >= now() - ($1 || ' days')::interval ${whereVal} GROUP BY 1 ORDER BY 1`, params);
  return { generated: gen.rows, validated: val.rows };
}
