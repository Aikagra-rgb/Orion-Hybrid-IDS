/**
 * Notifications Module
 * Dropdown panel toggle, mark-all-read functionality.
 */

export function initNotifications() {
  const btn = document.getElementById('notifBtn');
  const panel = document.getElementById('notifPanel');
  const badge = document.getElementById('notifBadge');
  const markAllBtn = document.getElementById('markAllRead');

  if (!btn || !panel) return;

  let isOpen = false;

  function toggle() {
    isOpen = !isOpen;
    panel.classList.toggle('notif-panel--open', isOpen);
  }

  function close() {
    isOpen = false;
    panel.classList.remove('notif-panel--open');
  }

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggle();
  });

  // Close when clicking outside
  document.addEventListener('click', (e) => {
    if (isOpen && !panel.contains(e.target) && !btn.contains(e.target)) {
      close();
    }
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen) close();
  });

  // Mark all read
  if (markAllBtn) {
    markAllBtn.addEventListener('click', () => {
      panel.querySelectorAll('.notif-item--unread').forEach(item => {
        item.classList.remove('notif-item--unread');
      });
      if (badge) badge.style.display = 'none';
    });
  }
}
