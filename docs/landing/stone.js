/** BASANOS hero: one faceted core, gold vein, quiet bloom. */
import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";

const VERDICTS = [
  { id: "PASS", color: 0x43e65a, phase: "alloy holds" },
  { id: "REVIEW", color: 0xffcc33, phase: "human verification" },
  { id: "FAIL", color: 0xe74c3c, phase: "contain this digest" },
];

export function mountTouchstone(canvas, opts = {}) {
  const host = canvas.parentElement || canvas;
  const compact = Boolean(opts.compact);
  const hud = opts.hud || null;
  const mobile = matchMedia("(max-width: 820px), (pointer: coarse)").matches || compact;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const renderer = new THREE.WebGLRenderer({
    canvas,
    alpha: true,
    antialias: true,
    powerPreference: "high-performance",
  });
  // The buffer is sized by hand and stretched by CSS, so three's own pixel-ratio
  // scaling stays out of the composer's viewport math.
  const dpr = Math.min(devicePixelRatio || 1, mobile ? 1.35 : 1.8);
  renderer.setPixelRatio(1);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.22;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(compact ? 40 : 36, 1, 0.1, 80);
  camera.position.set(0.35, compact ? 0.7 : 0.95, 5);

  const controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = 0.055;
  controls.enablePan = false;
  controls.rotateSpeed = 0.55;
  controls.autoRotate = !reduced;
  controls.autoRotateSpeed = 0.38;
  controls.target.set(0, 0, 0);

  // Object3D.add() returns the parent, so lights are positioned before adding.
  const key = new THREE.DirectionalLight(0xffe6b0, 2.1);
  key.position.set(3.4, 4.2, 3.8);
  const warm = new THREE.PointLight(0xe8c36a, 16, 24);
  warm.position.set(2.8, 1.6, 3.6);
  const cool = new THREE.PointLight(0x8ad4ff, 7, 20);
  cool.position.set(-3.8, -0.8, 2.2);
  scene.add(
    new THREE.AmbientLight(0x4a3b2b, 1.15),
    new THREE.HemisphereLight(0x93a7bd, 0x1b1309, 0.5),
    key,
    warm,
    cool,
  );

  const system = new THREE.Group();
  system.rotation.set(-0.14, 0.18, 0.08);
  scene.add(system);

  const core = new THREE.Mesh(
    new THREE.DodecahedronGeometry(1.52, 0),
    new THREE.MeshPhysicalMaterial({
      color: 0x6a6153,
      emissive: 0x3a2a12,
      emissiveIntensity: 0.14,
      metalness: 0.3,
      roughness: 0.34,
      clearcoat: 0.9,
      clearcoatRoughness: 0.16,
      sheen: 0.4,
      sheenColor: 0xe8c36a,
    }),
  );
  system.add(core);

  const wire = new THREE.Mesh(
    new THREE.DodecahedronGeometry(1.58, 0),
    new THREE.MeshBasicMaterial({
      color: 0xe8c36a,
      wireframe: true,
      transparent: true,
      opacity: 0.14,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  system.add(wire);

  // Additive back-facing shell: outlines the stone's silhouette against the void.
  const rim = new THREE.Mesh(
    new THREE.SphereGeometry(1.66, 40, 40),
    new THREE.MeshBasicMaterial({
      color: 0xe8c36a,
      transparent: true,
      opacity: 0.028,
      blending: THREE.AdditiveBlending,
      side: THREE.BackSide,
      depthWrite: false,
    }),
  );
  system.add(rim);

  const kernel = new THREE.Mesh(
    new THREE.OctahedronGeometry(0.46, 0),
    new THREE.MeshBasicMaterial({
      color: 0xffe3a0,
      transparent: true,
      opacity: 0.7,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  system.add(kernel);

  const vein = new THREE.Mesh(
    new THREE.TorusKnotGeometry(1.6, 0.026, 220, 12, 2, 3),
    new THREE.MeshPhysicalMaterial({
      color: 0xe0b24a,
      metalness: 1,
      roughness: 0.18,
      emissive: 0x6f4712,
      emissiveIntensity: 0.32,
      clearcoat: 0.6,
    }),
  );
  system.add(vein);

  const rings = new THREE.Group();
  system.add(rings);
  [
    [1.92, 0.012, 0xe8c36a, 0.72, 0.2, 0.12],
    [2.28, 0.009, 0x43e65a, -0.48, 0.7, 0.22],
    [2.62, 0.008, 0xffcc33, 0.4, -0.28, 0.8],
  ].forEach(([radius, tube, color, rx, ry, rz]) => {
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(radius, tube, 8, 160),
      new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.2,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    ring.rotation.set(rx, ry, rz);
    rings.add(ring);
  });

  const gems = VERDICTS.map((v, i) => {
    const angle = (i / 3) * Math.PI * 2 - 0.4;
    const group = new THREE.Group();
    group.position.set(Math.cos(angle) * 2.05, Math.sin(angle * 1.15) * 0.55, Math.sin(angle) * 2.05);
    const orb = new THREE.Mesh(
      new THREE.SphereGeometry(0.11, 20, 20),
      new THREE.MeshStandardMaterial({
        color: v.color,
        emissive: v.color,
        emissiveIntensity: 1.6,
        roughness: 0.22,
        metalness: 0.35,
      }),
    );
    const halo = new THREE.Mesh(
      new THREE.SphereGeometry(0.22, 16, 16),
      new THREE.MeshBasicMaterial({
        color: v.color,
        transparent: true,
        opacity: 0.1,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    group.add(orb, halo);
    system.add(group);
    return { group, halo, color: v.color };
  });

  const count = mobile ? 280 : 640;
  const positions = new Float32Array(count * 3);
  const colors = new Float32Array(count * 3);
  const palette = [new THREE.Color(0xe8c36a), new THREE.Color(0xc9b496), new THREE.Color(0x43e65a)];
  for (let i = 0; i < count; i++) {
    const r = 3.1 + Math.random() * 3.4;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
    positions[i * 3 + 1] = r * Math.cos(phi) * 0.58;
    positions[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
    const c = palette[(Math.random() * palette.length) | 0];
    colors.set([c.r, c.g, c.b], i * 3);
  }
  const dustGeo = new THREE.BufferGeometry();
  dustGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  dustGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  const dust = new THREE.Points(
    dustGeo,
    new THREE.PointsMaterial({
      size: 0.024,
      vertexColors: true,
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  system.add(dust);

  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  composer.addPass(new UnrealBloomPass(new THREE.Vector2(1, 1), compact ? 0.28 : 0.34, 0.6, 0.86));
  composer.addPass(new OutputPass());

  // The stone plus its rim: what must stay in frame at any aspect. Outer rings
  // are allowed to bleed off the edges.
  const FIT_RADIUS = 2.1;

  function frameCamera() {
    const half = Math.tan(THREE.MathUtils.degToRad(camera.fov) / 2);
    const distV = FIT_RADIUS / half;
    const distH = FIT_RADIUS / (half * camera.aspect);
    const dist = Math.max(distV, distH) * 1.04;
    controls.minDistance = dist * 0.55;
    controls.maxDistance = dist * 1.9;
    const dir = camera.position.clone().sub(controls.target);
    if (dir.lengthSq() < 1e-6) dir.set(0, 0.05, 1);
    camera.position.copy(controls.target).addScaledVector(dir.normalize(), dist);
    camera.updateProjectionMatrix();
  }

  function resize() {
    const box = canvas.getBoundingClientRect();
    const w = Math.max(1, Math.round(box.width || host.clientWidth));
    const h = Math.max(1, Math.round(box.height || host.clientHeight));
    const bw = Math.max(1, Math.round(w * dpr));
    const bh = Math.max(1, Math.round(h * dpr));
    renderer.setSize(bw, bh, false);
    composer.setSize(bw, bh);
    camera.aspect = w / h;
    camera.fov = compact ? 42 : 38;
    camera.updateProjectionMatrix();
    frameCamera();
  }
  resize();
  const ro = typeof ResizeObserver === "function" ? new ResizeObserver(resize) : null;
  if (ro) ro.observe(host);
  addEventListener("resize", resize);

  let vi = 0;
  function applyVerdict(index) {
    vi = index;
    const v = VERDICTS[vi];
    kernel.material.color.setHex(v.color);
    // The gold vein stays gold; the verdict only tints the facets faintly.
    core.material.emissive.setHex(v.color).multiplyScalar(0.02);
    core.material.emissiveIntensity = 1;
    gems.forEach((g, i) => {
      g.halo.material.opacity = i === vi ? 0.28 : 0.08;
    });
    if (hud && hud.verdict) {
      hud.verdict.textContent = v.id;
      hud.verdict.style.color = `#${v.color.toString(16).padStart(6, "0")}`;
    }
    if (hud && hud.phase) hud.phase.textContent = v.phase;
    // The page owns its own chrome (pips, labels); it just needs to be told which verdict is up.
    if (typeof opts.onVerdict === "function") opts.onVerdict(v.id, v);
  }
  applyVerdict(0);

  const clock = new THREE.Clock();
  let raf = 0;
  function frame() {
    raf = requestAnimationFrame(frame);
    const t = clock.getElapsedTime();
    if (!reduced) {
      core.rotation.y = t * 0.11;
      core.rotation.x = Math.sin(t * 0.23) * 0.06;
      wire.rotation.set(-t * 0.05, t * 0.09, t * 0.03);
      kernel.rotation.set(t * 0.26, -t * 0.32, t * 0.14);
      vein.rotation.y = t * 0.16;
      vein.rotation.z = t * 0.05;
      rings.rotation.y = t * 0.04;
      dust.rotation.y = -t * 0.016;
      kernel.scale.setScalar(1 + Math.sin(t * 2.05) * 0.04);
      gems.forEach((g, i) => {
        g.halo.scale.setScalar(1 + Math.sin(t * 2.2 + i) * 0.12);
      });
      if (!opts.freezeVerdict) {
        const next = Math.floor(t / 7) % VERDICTS.length;
        if (next !== vi) applyVerdict(next);
      }
    }
    controls.update();
    composer.render();
  }
  frame();

  return {
    setVerdict(id) {
      const i = VERDICTS.findIndex((v) => v.id === id);
      if (i >= 0) applyVerdict(i);
    },
    dispose() {
      cancelAnimationFrame(raf);
      removeEventListener("resize", resize);
      if (ro) ro.disconnect();
      controls.dispose();
      composer.dispose();
      renderer.dispose();
    },
  };
}
