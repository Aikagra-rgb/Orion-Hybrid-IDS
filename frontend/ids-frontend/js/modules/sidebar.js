/**
 * Sidebar Module
 * Handles sidebar toggle, collapse/expand, mobile overlay, and active nav state.
 * Integrates with Router for page navigation.
 */

import { navigateTo } from './router.js?v=20260502-1';

export function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  const sidebarToggle = document.getElementById('sidebarToggle');
  const mainContent = document.getElementById('mainContent');
  const navItems = document.querySelectorAll('.nav-item');

  if (!sidebar || !sidebarToggle) return;

  let isCollapsed = false;

  function toggleOverlay(show) {
    let overlay = document.querySelector('.sidebar-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'sidebar-overlay';
      document.body.appendChild(overlay);
      overlay.addEventListener('click', () => {
        sidebar.classList.remove('mobile-open');
        toggleOverlay(false);
      });
    }
    overlay.classList.toggle('active', show);
  }

  function toggle() {
    const isMobile = window.innerWidth <= 768;

    if (isMobile) {
      sidebar.classList.toggle('mobile-open');
      toggleOverlay(sidebar.classList.contains('mobile-open'));
    } else {
      isCollapsed = !isCollapsed;
      sidebar.classList.toggle('collapsed', isCollapsed);
      if (mainContent) {
        mainContent.style.marginLeft = isCollapsed
          ? 'var(--sidebar-collapsed)'
          : 'var(--sidebar-width)';
      }
    }
  }

  sidebarToggle.addEventListener('click', toggle);

  // Nav items — navigate to page on click
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const page = item.dataset.page;
      if (page) {
        navigateTo(page);
      }

      // Close mobile sidebar
      if (window.innerWidth <= 768) {
        sidebar.classList.remove('mobile-open');
        toggleOverlay(false);
      }
    });
  });
}
