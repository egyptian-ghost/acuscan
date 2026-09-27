/* ============================================================================
   AcuScan v6 — Main JavaScript
   ============================================================================ */

// ═══ Toast notifications ═══
function showToast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all .25s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ═══ Escape HTML ═══
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ═══ API helper ═══
async function apiFetch(url, options = {}) {
  const opts = Object.assign({
    headers: Object.assign(
      {'Content-Type': 'application/json'},
      options.headers || {}
    ),
  }, options);
  try {
    const r = await fetch(url, opts);
    if (r.status === 401) {
      window.location.href = '/login';
      throw new Error('Unauthorized');
    }
    if (!r.ok) {
      const err = await r.json().catch(() => ({error: 'HTTP ' + r.status}));
      throw new Error(err.error || 'HTTP ' + r.status);
    }
    return await r.json();
  } catch(e) {
    console.error('API error:', url, e);
    throw e;
  }
}

// ═══ Logout ═══
async function doLogout() {
  if (!confirm('Sign out?')) return;
  try {
    await fetch('/api/auth/logout', {method: 'POST'});
  } catch(e) {}
  window.location.href = '/login';
}

// ═══ Load current user ═══
async function loadCurrentUser() {
  try {
    const r = await fetch('/api/auth/me');
    const data = await r.json();
    if (data.authenticated) {
      const nameEl = document.getElementById('user-name');
      const roleEl = document.getElementById('user-role');
      const avEl = document.getElementById('user-avatar');
      if (nameEl) nameEl.textContent = data.user.username;
      if (roleEl) roleEl.textContent = data.user.role;
      if (avEl) avEl.textContent = (data.user.username[0] || 'U').toUpperCase();
    }
  } catch(e) {}
}

// ═══ Format helpers ═══
function formatDuration(seconds) {
  if (!seconds) return '-';
  if (seconds < 60) return seconds.toFixed(1) + 's';
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function formatDate(iso) {
  if (!iso) return '-';
  try {
    return iso.substring(0, 19).replace('T', ' ');
  } catch(e) { return iso; }
}

function shortUUID(uuid, len = 8) {
  return uuid ? uuid.substring(0, len) : '';
}

// ═══ Init ═══
document.addEventListener('DOMContentLoaded', () => {
  loadCurrentUser();

  // Auto-refresh dashboard when visible
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && window.location.pathname === '/') {
      if (typeof loadDashboard === 'function') loadDashboard();
    }
  });
});

// ═══ Global keyboard shortcuts ═══
document.addEventListener('keydown', (e) => {
  // Ctrl+K to focus search on findings page
  if (e.ctrlKey && e.key === 'k') {
    const searchInput = document.getElementById('search') || document.getElementById('findingsSearch');
    if (searchInput) {
      e.preventDefault();
      searchInput.focus();
    }
  }
  // Escape to close modals
  if (e.key === 'Escape') {
    const openModals = document.querySelectorAll('.modal.show');
    openModals.forEach(m => m.classList.remove('show'));
  }
});