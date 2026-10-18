import { useEffect, useRef } from "react";

export default function MatrixRain({ opacity = 0.55 }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    // Gracefully bypass in non-browser JSDOM test runner
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
    const fps = 28;
    const interval = 1000 / fps;

    const dpr = Math.max(1, window.devicePixelRatio || 1);
    let innerW = window.innerWidth;
    let innerH = window.innerHeight;

    const resize = () => {
      if (!canvas) return;
      innerW = window.innerWidth;
      innerH = window.innerHeight;
      canvas.width = innerW * dpr;
      canvas.height = innerH * dpr;
      canvas.style.width = `${innerW}px`;
      canvas.style.height = `${innerH}px`;
      if (ctx.scale) {
        ctx.scale(dpr, dpr);
      }
    };

    resize();

    const fontSize = 15;
    let columns = Math.ceil(innerW / fontSize);

    // Seed drops across the full viewport so 0,1 streams rain immediately on load
    let drops = Array(columns)
      .fill(0)
      .map(() => Math.floor(Math.random() * (innerH / fontSize)));

    const handleResize = () => {
      resize();
      columns = Math.ceil(innerW / fontSize);
      drops = Array(columns)
        .fill(0)
        .map(() => Math.floor(Math.random() * (innerH / fontSize)));
    };

    window.addEventListener("resize", handleResize);

    const chars = ["0", "1"];

    const draw = (currentTime) => {
      animationFrameId = requestAnimationFrame(draw);

      const delta = currentTime - lastTime;
      if (delta < interval) return;
      lastTime = currentTime - (delta % interval);

      // Trailing fade into light background (#F8FAFC)
      ctx.fillStyle = "rgba(248, 250, 252, 0.16)";
      ctx.fillRect(0, 0, innerW, innerH);

      ctx.font = `600 ${fontSize}px "IBM Plex Mono", "SFMono-Regular", Consolas, monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = chars[Math.floor(Math.random() * chars.length)];
        const x = i * fontSize;
        const y = drops[i] * fontSize;

        // Leading drop: vibrant electric cyan / bright blue
        const isLead = Math.random() > 0.85;
        if (isLead) {
          ctx.fillStyle = "#0284C7"; // Bright Cyan-600
        } else {
          ctx.fillStyle = "rgba(37, 99, 235, 0.78)"; // Vibrant Blue-600
        }

        ctx.fillText(text, x, y);

        // Reset to top once below viewport with random stagger
        if (y > innerH && Math.random() > 0.975) {
          drops[i] = 0;
        }

        drops[i]++;
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
      className="fixed inset-0 pointer-events-none z-0 transition-opacity duration-700"
      style={{ opacity, width: "100vw", height: "100vh" }}
      aria-hidden="true"
    />
  );
}
