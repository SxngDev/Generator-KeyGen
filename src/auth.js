import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
export const ROLE_ORDER = ['user','reseller','admin','owner'];
export function hasRoleOrAbove(userRole, targetRole){ return ROLE_ORDER.indexOf(userRole) >= ROLE_ORDER.indexOf(targetRole); }
export function sign(user){ const payload = { id:user.id, role:user.role, email:user.email, username:user.username }; return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }); }
export function auth(required = true){
  return (req,res,next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if(!token){ if(required) return res.status(401).json({error:'No token'}); req.user = null; return next(); }
    try{ req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }catch(e){ return res.status(401).json({error:'Invalid token'}); }
  };
}
export function requireRole(...roles){
  return (req,res,next)=>{
    if(!req.user) return res.status(401).json({error:'No auth'});
    const ok = roles.some(r => hasRoleOrAbove(req.user.role, r));
    if(!ok) return res.status(403).json({error:'Forbidden'});
    next();
  }
}
export async function hashPassword(p){ const salt = await bcrypt.genSalt(10); return bcrypt.hash(p, salt); }
export async function comparePassword(p, h){ return bcrypt.compare(p, h); }
