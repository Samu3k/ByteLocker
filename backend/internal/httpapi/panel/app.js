'use strict';
const byId = id => document.getElementById(id);
let token = '', cursor = null, timer = null, generation = 0, epoch = 0, request = null, busy = false, target = null;
function setBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll('[data-action]')) button.disabled = value;
  byId('confirm-delete').disabled = value || !target || byId('confirm-email').value.trim().toLowerCase() !== target.email;
}
function clearInvite() {
  byId('invitation-code').value = ''; byId('invitation-email').textContent = '';
  byId('invitation-expiry').textContent = ''; byId('invitation-result').hidden = true;
}
function closeDelete() {
  byId('delete-dialog').close(); target = null; byId('confirm-email').value = '';
  byId('delete-email').textContent = ''; byId('delete-message').textContent = ''; byId('confirm-delete').disabled = true;
}
function lock() {
  generation++; epoch++; request?.abort(); request = null; clearTimeout(timer);
  token = ''; cursor = null; byId('key').value = ''; byId('rows').replaceChildren();
  byId('email').value = ''; clearInvite(); closeDelete(); setBusy(false);
  byId('accounts').hidden = true; byId('login').hidden = false;
  byId('message').textContent = ''; byId('count').textContent = '';
}
function touch() { if (token) { clearTimeout(timer); timer = setTimeout(lock, 300000); } }
class PanelFailure extends Error {}
async function api(path, body) {
  const current = ++generation; request?.abort(); request = new AbortController();
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: { Authorization: 'Bearer ' + token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: request.signal,
    cache: 'no-store', credentials: 'omit', redirect: 'error'
  });
  if (current !== generation) return null;
  const result = response.status === 204 ? {} : await response.json();
  if (current !== generation) return null;
  if (response.status === 401) {
    lock(); byId('message').textContent = 'Chiave non valida o scaduta. Generane una nuova da CasaOS.'; return null;
  }
  if (!response.ok) {
    const messages = {
      account_exists: 'Questa email ha già un account sul server.',
      administrator_protected: 'Gli account amministratore non possono essere eliminati.',
      confirmation_mismatch: 'Account non trovato o email di conferma diversa. Aggiorna la lista.',
      invitation_limit: 'Limite degli inviti attivi raggiunto. Riprova dopo la loro scadenza.',
      invalid_request: 'Controlla email e durata dell’invito.',
      invalid_origin: 'Apri il pannello dal suo indirizzo HTTPS.'
    };
    throw new PanelFailure(messages[result.code] || 'Operazione non completata. Riprova tra poco.');
  }
  return result;
}
async function run(action, mutation = false) {
  if (busy) return;
  const currentEpoch = epoch;
  setBusy(true); byId('message').textContent = 'Operazione in corso…';
  try { await action(); }
  catch (error) {
    if (error.name === 'AbortError' || !token || epoch !== currentEpoch) return;
    const message = error instanceof PanelFailure ? error.message : mutation
      ? 'Connessione interrotta: l’operazione potrebbe essere riuscita. Aggiorna la lista prima di riprovare. Un codice d’invito non ricevuto non può essere recuperato.'
      : 'Connessione non riuscita. Riprova.';
    byId('message').textContent = message;
    if (byId('delete-dialog').open) byId('delete-message').textContent = message;
  } finally { if (token && epoch === currentEpoch) setBusy(false); }
}
async function load(after = null) {
  const page = await api('/api/v1/admin/accounts' + (after ? '?after=' + encodeURIComponent(after) : ''));
  if (!page) return;
  byId('rows').replaceChildren();
  for (const item of page.items) {
    const row = document.createElement('tr');
    for (const value of [item.email, item.role === 'admin' ? 'Amministratore' : 'Utente', new Date(item.created_at).toLocaleString('it-IT')]) {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    }
    const cell = document.createElement('td');
    if (item.role !== 'admin') {
      const button = document.createElement('button'); button.type = 'button'; button.className = 'danger secondary';
      button.textContent = 'Elimina'; button.dataset.action = ''; button.disabled = busy;
      button.setAttribute('aria-label', 'Elimina account ' + item.email);
      button.addEventListener('click', () => {
        if (busy) return;
        target = item; byId('delete-email').textContent = item.email; byId('confirm-email').value = ''; byId('delete-message').textContent = '';
        byId('confirm-delete').disabled = true; byId('delete-dialog').showModal(); byId('confirm-email').focus();
      });
      cell.append(button);
    } else cell.textContent = 'Protetto';
    row.append(cell); byId('rows').append(row);
  }
  cursor = page.next_after; byId('next').hidden = !cursor;
  byId('count').textContent = page.items.length + ' account in questa pagina';
  byId('login').hidden = true; byId('accounts').hidden = false;
  byId('message').textContent = ''; touch();
}
byId('access').addEventListener('submit', event => {
  event.preventDefault(); if (busy) return;
  if (location.protocol !== 'https:' && !['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname)) {
    byId('message').textContent = 'Apri il pannello tramite il collegamento HTTPS del server.'; return;
  }
  token = byId('key').value.trim(); byId('key').value = ''; touch(); run(() => load());
});
byId('invite-form').addEventListener('submit', event => {
  event.preventDefault(); if (busy) return;
  const email = byId('email').value.trim(), hours = Number(byId('ttl').value);
  clearInvite();
  run(async () => {
    const invitation = await api('/api/v1/admin/invitations', { email, ttl_hours: hours });
    if (!invitation) return;
    byId('invitation-code').value = invitation.invitation_secret;
    byId('invitation-email').textContent = invitation.email;
    byId('invitation-expiry').textContent = new Date(invitation.expires_at).toLocaleString('it-IT');
    byId('invitation-result').hidden = false;
    byId('message').textContent = 'Invito creato. Condividi privatamente il codice e l’indirizzo del server con il destinatario.';
  }, true);
});
byId('copy-invite').addEventListener('click', async () => {
  const current = generation;
  try {
    await navigator.clipboard.writeText(byId('invitation-code').value);
    if (token && current === generation) byId('message').textContent = 'Codice copiato. Condividilo soltanto con il destinatario.';
  } catch (_) { if (token && current === generation) byId('message').textContent = 'Seleziona e copia manualmente il codice.'; }
});
byId('confirm-email').addEventListener('input', () => setBusy(busy));
byId('delete-form').addEventListener('submit', event => {
  event.preventDefault(); if (busy || byId('confirm-delete').disabled || !target) return;
  const account = target;
  run(async () => {
    const result = await api('/api/v1/admin/accounts/delete', { account_id: account.account_id, confirm_email: byId('confirm-email').value.trim().toLowerCase() });
    if (!result) return;
    closeDelete(); await load();
    if (token) byId('message').textContent = 'Account eliminato. Sessioni e vault cifrato rimossi dal server.';
  }, true);
});
byId('cancel-delete').addEventListener('click', () => { if (!busy) closeDelete(); });
byId('delete-dialog').addEventListener('cancel', event => { if (busy) event.preventDefault(); else closeDelete(); });
byId('logout').addEventListener('click', lock);
byId('refresh').addEventListener('click', () => run(() => load()));
byId('next').addEventListener('click', () => run(() => load(cursor)));
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, touch);
window.addEventListener('pagehide', lock);
