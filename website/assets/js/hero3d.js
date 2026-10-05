// SVX hero: the Clasp X as a real-time 3D object.
// Geometry is extruded straight from the two paths in symbol.svg (64-unit grid).
import * as THREE from '../vendor/three.module.min.js';

const TOP = [[7,4],[19,4],[32,17],[45,4],[57,4],[32,29]];   // M7 4 H19 L32 17 L45 4 H57 L32 29 Z
const BOT = [[7,60],[19,60],[32,47],[45,60],[57,60],[32,35]]; // M7 60 H19 L32 47 L45 60 H57 L32 35 Z
const COLORS = { dark:{a:0xF3F1EC,b:0xFF6A3D}, light:{a:0x1D1F24,b:0xCF4A1F} };
const Z0 = 170, FOV = 30;
const clamp = (v,a=0,b=1)=>Math.min(b,Math.max(a,v));
const lerp = (a,b,t)=>a+(b-a)*t;
const easeOutExpo = t=>t>=1?1:1-Math.pow(2,-10*t);

function chevron(pts){
  // SVG is y-down; flip and centre on the grid so the clasp gap sits on the origin.
  const s = new THREE.Shape();
  pts.forEach(([x,y],i)=>{ const X=x-32, Y=32-y; i?s.lineTo(X,Y):s.moveTo(X,Y); });
  s.closePath();
  const g = new THREE.ExtrudeGeometry(s,{
    depth:7, steps:1, curveSegments:1,
    bevelEnabled:true, bevelThickness:.8, bevelSize:.6, bevelOffset:-.6, bevelSegments:3 // offset = -size keeps the silhouette (and the 6-unit gap) exact
  });
  g.translate(0,0,-3.5);
  return g;
}

export function init(host){
  const hero = host.closest('.hero') || host;
  let renderer;
  try { renderer = new THREE.WebGLRenderer({antialias:true,alpha:true,powerPreference:'high-performance'}); }
  catch(e){ return; }
  const small = matchMedia('(max-width:900px)').matches;
  renderer.setPixelRatio(Math.min(devicePixelRatio||1, small?1.5:2));
  renderer.domElement.setAttribute('aria-hidden','true');
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const cam = new THREE.PerspectiveCamera(FOV,1,1,1000);
  cam.position.set(0,0,Z0);
  scene.add(new THREE.AmbientLight(0xffffff,.9));
  const key = new THREE.DirectionalLight(0xffffff,2.1); key.position.set(60,90,140); scene.add(key);
  const rim = new THREE.DirectionalLight(0xffffff,.9); rim.position.set(-90,-40,-80); scene.add(rim);

  const theme = ()=>document.documentElement.dataset.theme==='light'?'light':'dark';
  const matA = new THREE.MeshStandardMaterial({roughness:.5,metalness:.05});
  const matB = new THREE.MeshStandardMaterial({roughness:.45,metalness:.05});
  const paint = ()=>{ const c=COLORS[theme()]; matA.color.setHex(c.a); matB.color.setHex(c.b); };
  paint();
  addEventListener('svx:theme',()=>{ paint(); draw(); });

  const group = new THREE.Group();
  const top = new THREE.Mesh(chevron(TOP),matA);
  const bot = new THREE.Mesh(chevron(BOT),matB);
  group.add(top,bot); scene.add(group);

  // Desktop: the logo sits in the right third, clear of the headline. Phones and
  // tablets: the canvas is its own band above the copy, so the logo is centred.
  const band = matchMedia('(max-width:900px)');
  let baseX=0, baseY=0, baseS=1;
  function layout(){
    const w=host.clientWidth, h=host.clientHeight; if(!w||!h) return;
    renderer.setSize(w,h,false);
    cam.aspect=w/h; cam.updateProjectionMatrix();
    const visH = 2*Z0*Math.tan(FOV*Math.PI/360), visW = visH*cam.aspect;
    // the symbol's box on the grid is 50 x 56 units
    if (band.matches){ baseX=0; baseY=0; baseS=Math.min(visW*.5/50, visH*.72/56); }
    else { baseX=visW*.25; baseY=0; baseS=Math.min(visW*.27/50, visH*.6/56); }
    draw();
  }
  band.addEventListener('change',layout);
  new ResizeObserver(layout).observe(host);

  // pointer parallax
  let px=0,py=0,tx=0,ty=0;
  addEventListener('pointermove',e=>{ tx=e.clientX/innerWidth*2-1; ty=e.clientY/innerHeight*2-1; },{passive:true});

  // scroll progress through the (tall, sticky) hero
  let sp=0;
  const scrollP = ()=>{ const r=hero.getBoundingClientRect(); const d=r.height-innerHeight; return d>0?clamp(-r.top/d):0; };

  const t0 = performance.now();
  function frame(now){
    const t = now-t0;
    const eA = easeOutExpo(clamp((t-150)/1700));
    const eB = easeOutExpo(clamp((t-300)/1700));
    // the two chevrons slide in from opposite sides and stop at their grid positions, gap intact
    top.position.x = lerp(-150,0,eA); top.rotation.z = (1-eA)*-.35;
    bot.position.x = lerp( 150,0,eB); bot.rotation.z = (1-eB)* .35;

    px+= (tx-px)*.06; py+= (ty-py)*.06;
    sp+= (scrollP()-sp)*.1;
    // Scroll: the logo turns (never edge-on), drifts to the centre and the camera moves in.
    group.rotation.y = Math.sin(t*.00045)*.14 + px*.32 + sp*.62;
    group.rotation.x = Math.cos(t*.00035)*.05 + py*.18 + sp*.26;
    group.position.set(baseX*(1-sp), baseY, 0);
    group.scale.setScalar(baseS);
    cam.position.z = Z0 - sp*40;
  }
  function draw(){ renderer.render(scene,cam); }

  let running=false, raf=0, live=false;
  function loop(now){ frame(now); draw(); if(!live){ live=true; host.classList.add('is-live'); } if(running) raf=requestAnimationFrame(loop); }
  const start=()=>{ if(running||document.hidden) return; running=true; raf=requestAnimationFrame(loop); };
  const stop =()=>{ running=false; cancelAnimationFrame(raf); };
  let visible=true;
  new IntersectionObserver(([e])=>{ visible=e.isIntersecting; visible?start():stop(); }).observe(hero);
  document.addEventListener('visibilitychange',()=>{ document.hidden?stop():visible&&start(); });
  layout(); start();
}
