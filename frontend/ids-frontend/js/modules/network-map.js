/**
 * Network Map Module - ORION INTEGRATED
 * Canvas-based node graph that reacts to live backend threats.
 */

const NODES = [
  { id: 'firewall',  label: 'Firewall',      x: 0.50, y: 0.10, type: 'security' },
  { id: 'router',    label: 'Core Router',    x: 0.50, y: 0.30, type: 'network' },
  { id: 'switch1',   label: 'Switch A',       x: 0.25, y: 0.50, type: 'network' },
  { id: 'switch2',   label: 'Switch B',       x: 0.75, y: 0.50, type: 'network' },
  { id: 'server1',   label: 'Web Server',     x: 0.12, y: 0.75, type: 'server' },
  { id: 'server2',   label: 'DB Server',      x: 0.38, y: 0.75, type: 'server' },
  { id: 'server3',   label: 'App Server',     x: 0.62, y: 0.75, type: 'server' },
  { id: 'ids',       label: 'ORION IDS',      x: 0.88, y: 0.75, type: 'security' },
  { id: 'internet',  label: 'Internet',       x: 0.50, y: 0.95, type: 'external' },
];

const EDGES = [
  ['firewall', 'router'], ['router', 'switch1'], ['router', 'switch2'],
  ['switch1', 'server1'], ['switch1', 'server2'], ['switch2', 'server3'],
  ['switch2', 'ids'], ['router', 'internet'],
];

const TYPE_COLORS = {
  security: '#6b7cff', network: '#3dd68c', server: '#a78bfa', external: '#f0c541',
  threat: '#ff4444' // New threat color
};

export function initNetworkMap() {
  const canvas = document.getElementById('networkMapCanvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let width, height, particles = [], animId;
  let lastAlertId = 0; // Tracks the last alert we saw

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    width = rect.width; height = rect.height;
    canvas.width = width * dpr; canvas.height = height * dpr;
    canvas.style.width = width + 'px'; canvas.style.height = height + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  const nodeById = (id) => NODES.find(n => n.id === id);
  const getPos = (node) => ({ x: node.x * width, y: node.y * height });

  // --- NEW: Function to spawn a Red Attack Particle ---
  function spawnAttackParticle() {
    particles.push({
      from: nodeById('internet'),
      to: nodeById('ids'),
      progress: 0,
      speed: 0.01, // Attacks move faster
      size: 4,
      color: TYPE_COLORS.threat,
      isAttack: true
    });
  }

  // --- NEW: Poll the Backend for new alerts ---
  async function checkNewThreats() {
    try {
      const res = await fetch('/api/alerts');
      const alerts = await res.json();
      if (alerts.length > 0) {
        const latest = alerts[0];
        if (latest.id > lastAlertId) {
          spawnAttackParticle(); // Trigger visual attack on map
          lastAlertId = latest.id;
        }
      }
    } catch (e) { console.error("Map fetch failed", e); }
  }

  function spawnParticle() {
    const edge = EDGES[Math.floor(Math.random() * EDGES.length)];
    const from = nodeById(edge[0]); const to = nodeById(edge[1]);
    particles.push({
      from, to, progress: 0,
      speed: 0.003 + Math.random() * 0.004,
      size: 1.5 + Math.random() * 1.5,
      color: TYPE_COLORS[to.type] || '#6b7cff'
    });
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    
    // Draw Edges
    EDGES.forEach(([aId, bId]) => {
      const a = getPos(nodeById(aId)), b = getPos(nodeById(bId));
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = 'rgba(35, 39, 47, 0.4)'; ctx.stroke();
    });

    // Update & Draw Particles
    if (Math.random() < 0.1) spawnParticle();
    particles = particles.filter(p => {
      p.progress += p.speed;
      const a = getPos(p.from), b = getPos(p.to);
      const x = a.x + (b.x - a.x) * p.progress;
      const y = a.y + (b.y - a.y) * p.progress;
      
      ctx.beginPath(); ctx.arc(x, y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color; ctx.fill();
      return p.progress < 1;
    });

    // Draw Nodes
    NODES.forEach(node => {
      const pos = getPos(node);
      const color = TYPE_COLORS[node.type];
      ctx.beginPath(); ctx.arc(pos.x, pos.y, 6, 0, Math.PI * 2);
      ctx.fillStyle = color; ctx.fill();
      ctx.fillStyle = '#8b8f9a'; ctx.fillText(node.label, pos.x, pos.y - 16);
    });

    animId = requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener('resize', resize);
  const pollInterval = setInterval(checkNewThreats, 3000); // Check every 3s
  draw();

  return () => {
    cancelAnimationFrame(animId);
    clearInterval(pollInterval);
    window.removeEventListener('resize', resize);
  };
}