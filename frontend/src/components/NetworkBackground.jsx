import { useEffect, useRef } from "react";

export default function NetworkBackground({ opacity = 0.22 }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    // Gracefully bypass in JSDOM test runner
    if (typeof window !== "undefined" && window.navigator?.userAgent?.includes("jsdom")) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    let ctx;
    try {
      ctx = canvas.getContext("2d");
    } catch {
      return;
    }
    if (!ctx) return;

    let animationFrameId;
    let lastTime = 0;
    const fps = 30;
    const interval = 1000 / fps;

    const dpr = Math.max(1, window.devicePixelRatio || 1);
    let width = window.innerWidth;
    let height = window.innerHeight;

    const resize = () => {
      if (!canvas) return;
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      if (ctx.scale) {
        ctx.scale(dpr, dpr);
      }
    };

    resize();

    // Node count scaled to screen size for balanced density
    const nodeCount = Math.min(55, Math.max(25, Math.floor((width * height) / 28000)));
    const maxDistance = 140;

    // Create network nodes (routers/servers)
    const nodes = [];
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        radius: Math.random() * 1.6 + 1.8, // 1.8px - 3.4px
        pulse: Math.random() * Math.PI * 2,
        isIPv6: Math.random() > 0.45, // visual variety in node tones
      });
    }

    // Packet data traveling along links
    const packets = [];
    const spawnPacket = (fromNode, toNode) => {
      if (packets.length > 12) return;
      packets.push({
        from: fromNode,
        to: toNode,
        progress: 0,
        speed: 0.012 + Math.random() * 0.015,
        color: fromNode.isIPv6 ? "#2563EB" : "#0284C7",
      });
    };

    const handleResize = () => {
      resize();
    };

    window.addEventListener("resize", handleResize);

    const draw = (currentTime) => {
      animationFrameId = requestAnimationFrame(draw);

      const delta = currentTime - lastTime;
      if (delta < interval) return;
      lastTime = currentTime - (delta % interval);

      ctx.clearRect(0, 0, width, height);

      // Update node positions with gentle floating
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;
        n.pulse += 0.03;

        // Bounce smoothly off viewport edges
        if (n.x < 0) { n.x = 0; n.vx *= -1; }
        else if (n.x > width) { n.x = width; n.vx *= -1; }

        if (n.y < 0) { n.y = 0; n.vy *= -1; }
        else if (n.y > height) { n.y = height; n.vy *= -1; }
      }

      // Draw connection lines between nearby nodes
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * 0.35;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(59, 130, 246, ${alpha})`;
            ctx.lineWidth = 1;
            ctx.stroke();

            // Randomly spawn a traveling packet on close links
            if (dist < 90 && Math.random() < 0.003) {
              spawnPacket(a, b);
            }
          }
        }
      }

      // Update and draw traveling data packets
      for (let p = packets.length - 1; p >= 0; p--) {
        const pkt = packets[p];
        pkt.progress += pkt.speed;
        if (pkt.progress >= 1) {
          packets.splice(p, 1);
          continue;
        }

        const px = pkt.from.x + (pkt.to.x - pkt.from.x) * pkt.progress;
        const py = pkt.from.y + (pkt.to.y - pkt.from.y) * pkt.progress;

        ctx.beginPath();
        ctx.arc(px, py, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = pkt.color;
        ctx.shadowColor = pkt.color;
        ctx.shadowBlur = 4;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Draw nodes (routers/servers)
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        const pulseSize = Math.sin(n.pulse) * 0.4;
        const currentR = Math.max(1, n.radius + pulseSize);

        // Subtle outer aura
        ctx.beginPath();
        ctx.arc(n.x, n.y, currentR + 2.5, 0, Math.PI * 2);
        ctx.fillStyle = n.isIPv6 ? "rgba(37, 99, 235, 0.08)" : "rgba(2, 132, 199, 0.08)";
        ctx.fill();

        // Node core
        ctx.beginPath();
        ctx.arc(n.x, n.y, currentR, 0, Math.PI * 2);
        ctx.fillStyle = n.isIPv6 ? "#2563EB" : "#0284C7";
        ctx.fill();
      }
    };

    animationFrameId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 transition-opacity duration-1000"
      style={{ opacity, width: "100vw", height: "100vh" }}
      aria-hidden="true"
    />
  );
}
