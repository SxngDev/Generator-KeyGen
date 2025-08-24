export function generateKey({ groups = 4, groupLen = 5, prefix = '' } = {}) {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const randGroup = () => Array.from({length: groupLen}, () => alphabet[Math.floor(Math.random()*alphabet.length)]).join('');
  const body = Array.from({length: groups}, randGroup).join('-');
  return prefix ? `${prefix}-${body}` : body;
}
export function remainingSeconds(expiresAt) {
  if (!expiresAt) return null;
  const diff = (new Date(expiresAt).getTime() - Date.now())/1000;
  return Math.max(0, Math.floor(diff));
}
export function addDays(date, days) { const d = new Date(date); d.setDate(d.getDate()+days); return d; }
