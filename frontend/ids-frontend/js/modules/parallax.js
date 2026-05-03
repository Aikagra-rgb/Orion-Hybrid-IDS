/**
 * Parallax Module
 * Subtle background movement on mouse move.
 */

export function initParallax() {
  const bg = document.getElementById('parallaxBg');
  if (!bg) return;

  document.addEventListener('mousemove', (e) => {
    const x = (e.clientX / window.innerWidth - 0.5) * 20;
    const y = (e.clientY / window.innerHeight - 0.5) * 20;
    bg.style.transform = `translate(${x}px, ${y}px)`;
  });
}
