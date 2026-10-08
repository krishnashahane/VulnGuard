// Adapted from React Bits "Particles" (reactbits.dev, MIT). Pauses offscreen, honours reduced motion.
import { useEffect, useRef } from 'react';
import { Renderer, Camera, Geometry, Program, Mesh } from 'ogl';

const vertex = /* glsl */ `
  attribute vec3 position;
  attribute vec4 random;
  attribute vec3 color;
  uniform mat4 modelMatrix;
  uniform mat4 viewMatrix;
  uniform mat4 projectionMatrix;
  uniform float uTime;
  uniform float uSpread;
  uniform float uBaseSize;
  uniform float uSizeRandomness;
  varying vec4 vRandom;
  varying vec3 vColor;

  void main() {
    vRandom = random;
    vColor = color;
    vec3 pos = position * uSpread;
    pos.z *= 10.0;
    vec4 mPos = modelMatrix * vec4(pos, 1.0);
    float t = uTime;
    mPos.x += sin(t * random.z + 6.28 * random.w) * mix(0.1, 1.5, random.x);
    mPos.y += sin(t * random.y + 6.28 * random.x) * mix(0.1, 1.5, random.w);
    mPos.z += sin(t * random.w + 6.28 * random.y) * mix(0.1, 1.5, random.z);
    vec4 mvPos = viewMatrix * mPos;
    gl_PointSize = (uBaseSize * (1.0 + uSizeRandomness * (random.x - 0.5))) / length(mvPos.xyz);
    gl_Position = projectionMatrix * mvPos;
  }
`;

const fragment = /* glsl */ `
  precision highp float;
  uniform float uTime;
  uniform float uOpacity;
  varying vec4 vRandom;
  varying vec3 vColor;

  void main() {
    vec2 uv = gl_PointCoord.xy;
    float d = length(uv - vec2(0.5));
    float circle = smoothstep(0.5, 0.35, d);
    gl_FragColor = vec4(vColor + 0.15 * sin(uv.yxx + uTime + vRandom.y * 6.28), circle * uOpacity);
  }
`;

function hexToRgb(hex) {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
  const n = parseInt(full, 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

export default function Particles({
  colors = ['#4ade80', '#94a3b8'],
  count = 180,
  spread = 10,
  speed = 0.08,
  baseSize = 90,
  opacity = 0.7,
  className = '',
}) {
  const containerRef = useRef(null);
  const colorKey = colors.join(',');

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const small = window.innerWidth < 768;
    const total = small ? Math.round(count * 0.5) : count;

    let renderer;
    try {
      renderer = new Renderer({ depth: false, alpha: true, dpr: Math.min(window.devicePixelRatio, small ? 1.5 : 2) });
    } catch {
      return; // WebGL unavailable: the page works fine without the backdrop
    }
    const gl = renderer.gl;
    gl.canvas.setAttribute('aria-hidden', 'true');
    gl.canvas.style.width = '100%';
    gl.canvas.style.height = '100%';
    container.appendChild(gl.canvas);
    gl.clearColor(0, 0, 0, 0);

    const camera = new Camera(gl, { fov: 15 });
    camera.position.set(0, 0, 20);

    const resize = () => {
      renderer.setSize(container.clientWidth, container.clientHeight);
      camera.perspective({ aspect: gl.canvas.width / Math.max(gl.canvas.height, 1) });
    };
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(container);
    resize();

    const palette = colorKey.split(',').map(hexToRgb);
    const positions = new Float32Array(total * 3);
    const randoms = new Float32Array(total * 4);
    const tints = new Float32Array(total * 3);
    for (let i = 0; i < total; i++) {
      let x, y, z, len;
      do {
        x = Math.random() * 2 - 1;
        y = Math.random() * 2 - 1;
        z = Math.random() * 2 - 1;
        len = x * x + y * y + z * z;
      } while (len > 1 || len === 0);
      const r = Math.cbrt(Math.random());
      positions.set([x * r, y * r, z * r], i * 3);
      randoms.set([Math.random(), Math.random(), Math.random(), Math.random()], i * 4);
      tints.set(palette[Math.floor(Math.random() * palette.length)], i * 3);
    }

    const geometry = new Geometry(gl, {
      position: { size: 3, data: positions },
      random: { size: 4, data: randoms },
      color: { size: 3, data: tints },
    });
    const program = new Program(gl, {
      vertex,
      fragment,
      uniforms: {
        uTime: { value: 0 },
        uSpread: { value: spread },
        uBaseSize: { value: baseSize },
        uSizeRandomness: { value: 1 },
        uOpacity: { value: opacity },
      },
      transparent: true,
      depthTest: false,
    });
    const mesh = new Mesh(gl, { mode: gl.POINTS, geometry, program });

    let frame = 0;
    let visible = true;
    let last = performance.now();
    let elapsed = 0;

    const render = (t) => {
      const delta = t - last;
      last = t;
      elapsed += delta * speed;
      program.uniforms.uTime.value = elapsed * 0.001;
      mesh.rotation.x = Math.sin(elapsed * 0.0002) * 0.1;
      mesh.rotation.y = Math.cos(elapsed * 0.0005) * 0.15;
      mesh.rotation.z += 0.01 * speed;
      renderer.render({ scene: mesh, camera });
    };

    const loop = (t) => {
      if (visible) render(t);
      frame = requestAnimationFrame(loop);
    };

    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      last = performance.now();
    });
    io.observe(container);

    if (reduceMotion) render(performance.now());
    else frame = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(frame);
      io.disconnect();
      resizeObserver.disconnect();
      if (container.contains(gl.canvas)) container.removeChild(gl.canvas);
      gl.getExtension('WEBGL_lose_context')?.loseContext();
    };
  }, [colorKey, count, spread, speed, baseSize, opacity]);

  return <div ref={containerRef} className={`pointer-events-none ${className}`} />;
}
