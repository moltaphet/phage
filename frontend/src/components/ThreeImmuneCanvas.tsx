import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Eye, Pause, Play } from 'lucide-react';

interface ThreeImmuneCanvasProps {
  quarantinedCount?: number;
  activeThreatAlert?: boolean;
}

export function ThreeImmuneCanvas({
  quarantinedCount = 3,
  activeThreatAlert = false,
}: ThreeImmuneCanvasProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [viewMode, setViewMode] = useState<'nanobot' | 'network'>('nanobot');
  const [isRotating, setIsRotating] = useState(true);

  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) setIsRotating(false);
  }, []);

  useEffect(() => {
    const currentMount = mountRef.current;
    if (!currentMount) return;

    const width = currentMount.clientWidth || 420;
    const height = currentMount.clientHeight || 420;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 1000);
    camera.position.set(0, 0.4, 12);

    const probe = document.createElement('canvas');
    const hasGl = Boolean(probe.getContext('webgl2') || probe.getContext('webgl'));
    if (!hasGl) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, canvas: document.createElement('canvas') });
    } catch {
      return;
    }
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    currentMount.appendChild(renderer.domElement);
    currentMount.dataset.live = '1';

    scene.add(new THREE.AmbientLight(0xe8dcc4, 0.55));

    const key = new THREE.DirectionalLight(0xc9783a, 2.1);
    key.position.set(5, 7, 6);
    scene.add(key);

    const fill = new THREE.DirectionalLight(0x5a9a96, 1.4);
    fill.position.set(-6, -2, 4);
    scene.add(fill);

    const rim = new THREE.DirectionalLight(0xe8dcc4, 0.7);
    rim.position.set(0, -8, -6);
    scene.add(rim);

    const phageGroup = new THREE.Group();

    const capsidGeo = new THREE.IcosahedronGeometry(1.55, 0);
    const capsidMat = new THREE.MeshStandardMaterial({
      color: activeThreatAlert ? 0xc45c52 : 0xc9783a,
      metalness: 0.55,
      roughness: 0.32,
      flatShading: true,
      emissive: activeThreatAlert ? 0x8d3f39 : 0x5a3214,
      emissiveIntensity: 0.25,
    });
    const capsidMesh = new THREE.Mesh(capsidGeo, capsidMat);
    capsidMesh.position.y = 2.05;
    phageGroup.add(capsidMesh);

    const wire = new THREE.LineSegments(
      new THREE.WireframeGeometry(capsidGeo),
      new THREE.LineBasicMaterial({
        color: 0xe8dcc4,
        transparent: true,
        opacity: 0.45,
      })
    );
    wire.position.y = 2.05;
    phageGroup.add(wire);

    const core = new THREE.Mesh(
      new THREE.OctahedronGeometry(0.62, 0),
      new THREE.MeshBasicMaterial({ color: 0x5a9a96, wireframe: true })
    );
    core.position.y = 2.05;
    phageGroup.add(core);

    const metalMat = new THREE.MeshStandardMaterial({
      color: 0x8a8274,
      metalness: 0.82,
      roughness: 0.28,
    });

    const collar = new THREE.Mesh(new THREE.CylinderGeometry(0.42, 0.42, 0.22, 12), metalMat);
    collar.position.y = 0.95;
    phageGroup.add(collar);

    const sheath = new THREE.Mesh(
      new THREE.CylinderGeometry(0.32, 0.32, 2.15, 16),
      new THREE.MeshStandardMaterial({ color: 0x3d6f6c, metalness: 0.7, roughness: 0.3 })
    );
    sheath.position.y = -0.25;
    phageGroup.add(sheath);

    for (let r = 0; r < 5; r++) {
      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(0.4, 0.045, 8, 24),
        new THREE.MeshStandardMaterial({ color: 0xc9783a, metalness: 0.9, roughness: 0.15 })
      );
      ring.rotation.x = Math.PI / 2;
      ring.position.y = -1.1 + r * 0.42;
      phageGroup.add(ring);
    }

    const base = new THREE.Mesh(new THREE.CylinderGeometry(0.72, 0.82, 0.22, 6), metalMat);
    base.position.y = -1.45;
    phageGroup.add(base);

    const tailFibers: THREE.Group[] = [];
    for (let i = 0; i < 6; i++) {
      const angle = (i / 6) * Math.PI * 2;
      const leg = new THREE.Group();
      leg.position.set(Math.cos(angle) * 0.7, -1.45, Math.sin(angle) * 0.7);

      const upper = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.05, 1.4, 8), metalMat);
      upper.position.set(Math.cos(angle) * 0.4, -0.6, Math.sin(angle) * 0.4);
      upper.rotation.z = Math.cos(angle) * 0.6;
      upper.rotation.x = -Math.sin(angle) * 0.6;
      leg.add(upper);

      const lower = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.035, 1.55, 8), metalMat);
      lower.position.set(Math.cos(angle) * 0.9, -1.6, Math.sin(angle) * 0.9);
      lower.rotation.z = -Math.cos(angle) * 0.4;
      lower.rotation.x = Math.sin(angle) * 0.4;
      leg.add(lower);

      phageGroup.add(leg);
      tailFibers.push(leg);
    }

    scene.add(phageGroup);

    const particleCount = 140;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleColors = new Float32Array(particleCount * 3);
    const gold = new THREE.Color(0xc9783a);
    const teal = new THREE.Color(0x5a9a96);
    const red = new THREE.Color(0xc45c52);
    const ivory = new THREE.Color(0xe8dcc4);

    for (let p = 0; p < particleCount; p++) {
      const radius = 3.4 + Math.random() * 4.2;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(Math.random() * 2 - 1);
      particlePositions[p * 3] = radius * Math.sin(phi) * Math.cos(theta);
      particlePositions[p * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      particlePositions[p * 3 + 2] = radius * Math.cos(phi);
      const nodeColor = p < quarantinedCount ? red : Math.random() > 0.55 ? gold : Math.random() > 0.5 ? teal : ivory;
      particleColors[p * 3] = nodeColor.r;
      particleColors[p * 3 + 1] = nodeColor.g;
      particleColors[p * 3 + 2] = nodeColor.b;
    }

    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    particleGeo.setAttribute('color', new THREE.BufferAttribute(particleColors, 3));
    const particleSystem = new THREE.Points(
      particleGeo,
      new THREE.PointsMaterial({ size: 0.12, vertexColors: true, transparent: true, opacity: 0.8 })
    );
    scene.add(particleSystem);

    const lineIndices: number[] = [];
    for (let a = 0; a < particleCount; a += 4) {
      for (let b = a + 1; b < particleCount; b += 8) {
        const dx = particlePositions[a * 3] - particlePositions[b * 3];
        const dy = particlePositions[a * 3 + 1] - particlePositions[b * 3 + 1];
        const dz = particlePositions[a * 3 + 2] - particlePositions[b * 3 + 2];
        if (Math.sqrt(dx * dx + dy * dy + dz * dz) < 2.4) lineIndices.push(a, b);
      }
    }
    const linesGeo = new THREE.BufferGeometry();
    linesGeo.setIndex(lineIndices);
    linesGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const linesMesh = new THREE.LineSegments(
      linesGeo,
      new THREE.LineBasicMaterial({ color: 0xb8ab94, transparent: true, opacity: 0.18 })
    );
    scene.add(linesMesh);

    let targetX = 0;
    let targetY = 0;
    const handleMouseMove = (event: MouseEvent) => {
      const rect = currentMount.getBoundingClientRect();
      targetX = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      targetY = -(((event.clientY - rect.top) / rect.height) * 2 - 1);
    };
    currentMount.addEventListener('mousemove', handleMouseMove);

    const handleResize = () => {
      const w = currentMount.clientWidth;
      const h = currentMount.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    const clock = new THREE.Clock();
    let frame = 0;
    const animate = () => {
      frame = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();
      phageGroup.position.y = Math.sin(t * 1.2) * 0.18;
      tailFibers.forEach((fiber, idx) => {
        fiber.position.y = -1.45 + Math.sin(t * 1.8 + idx) * 0.03;
      });
      core.rotation.y = t * 1.4;
      core.rotation.x = t * 0.7;
      if (isRotating) {
        phageGroup.rotation.y += 0.005;
        particleSystem.rotation.y += 0.0016;
        linesMesh.rotation.y += 0.0016;
      }
      phageGroup.rotation.x += (targetY * 0.35 - phageGroup.rotation.x) * 0.04;
      phageGroup.rotation.z += (-targetX * 0.28 - phageGroup.rotation.z) * 0.04;
      const zoom = viewMode === 'network' ? 15.5 : 12;
      camera.position.z += (zoom - camera.position.z) * 0.06;
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frame);
      currentMount.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      if (renderer.domElement.parentNode === currentMount) {
        currentMount.removeChild(renderer.domElement);
      }
      renderer.dispose();
      capsidGeo.dispose();
      capsidMat.dispose();
    };
  }, [viewMode, isRotating, activeThreatAlert, quarantinedCount]);

  return (
    <div className="scope-frame">
      <div className="scope" aria-label="Electron microscope viewport of a bacteriophage sentinel">
        <div ref={mountRef} className="scope-stage">
          <svg className="scope-fallback" viewBox="0 0 200 220" aria-hidden="true">
            <polygon points="100,18 148,46 148,102 100,130 52,102 52,46" fill="#C9783A" />
            <polygon points="100,18 148,46 148,102 100,130 52,102 52,46" fill="none" stroke="#E8DCC4" strokeWidth="1.2" opacity="0.45" />
            <circle cx="100" cy="74" r="16" fill="#090C10" />
            <rect x="94" y="128" width="12" height="42" rx="2" fill="#5A9A96" />
            <path d="M100 170 L68 206 M100 170 L132 206 M100 170 L100 214" stroke="#E8DCC4" strokeWidth="3" strokeLinecap="round" fill="none" />
          </svg>
        </div>
        <div className="scope-hair" />
        <div className="scope-scan" />
        <div className="scope-label">SEM · T4 sentinel · live</div>
        <div className="scope-scale">200 nm</div>
      </div>
      <div className="scope-controls">
        <button
          type="button"
          className="btn btn-ghost"
          style={{ minHeight: 36, padding: '0 12px', fontSize: 12 }}
          onClick={() => setViewMode(viewMode === 'nanobot' ? 'network' : 'nanobot')}
        >
          <Eye size={14} aria-hidden="true" />
          {viewMode === 'nanobot' ? 'Field' : 'Specimen'}
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          style={{ minHeight: 36, padding: '0 12px', fontSize: 12 }}
          onClick={() => setIsRotating(!isRotating)}
        >
          {isRotating ? <Pause size={14} aria-hidden="true" /> : <Play size={14} aria-hidden="true" />}
          {isRotating ? 'Hold' : 'Orbit'}
        </button>
      </div>
    </div>
  );
}
