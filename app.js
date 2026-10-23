/* JASAN Móvil · el celular arma el pedido, lo cifra y lo deja en el buzón; la PC del mismo usuario lo hace.
   Protocolo (igual a app/movil.py de JASAN):
     enlace  …/#j=<b64url JSON {v,u,k,t,id,n,r}>
     caja    = sha256("jasan-movil|"+t) en hex, 32 primeros
     clave   = sha256("jasan-movil-k|"+t) → AES-256-GCM; blob = nonce12 | cifrado | tag16
     rutas   movil/<caja>/pedidos/<id>.bin · resultados/<id>.bin · pc.bin · anulado            */
"use strict";
const VERSION = "1.0 (JASAN 2.39.0)";
const BUCKET = "jasan", TOPE_MB = 15, VIVO_SEG = 90;
const $ = (q, el = document) => el.querySelector(q);
const $$ = (q, el = document) => [...el.querySelectorAll(q)];
const enc = new TextEncoder(), dec = new TextDecoder();

// ---------------------------------------------------------------- utilidades
function b64uDec(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "=".repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function b64Enc(u8) { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
function b64Dec(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, "0")).join("");
const sha = async s => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nuevoId = () => hex(crypto.getRandomValues(new Uint8Array(6)));
function tam(n) { return n > 1048576 ? (n / 1048576).toFixed(1).replace(".", ",") + " MB" : Math.max(1, Math.round(n / 1024)) + " KB"; }
function isoLocal(d = new Date()) { const z = -d.getTimezoneOffset(), p = n => String(Math.abs(n)).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}${z >= 0 ? "+" : "-"}${p(z / 60 | 0)}:${p(z % 60)}`; }
function hace(t) { const s = (Date.now() - new Date(t).getTime()) / 1000; if (!isFinite(s)) return "";
  if (s < 60) return "hace un momento"; if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`; const d = new Date(t);
  return d.toLocaleDateString("es-PE", { day: "numeric", month: "short" }) + " · " + d.toLocaleTimeString("es-PE", { hour: "2-digit", minute: "2-digit" }); }
const MESES = ["ENERO", "FEBRERO", "MARZO", "ABRIL", "MAYO", "JUNIO", "JULIO", "AGOSTO", "SETIEMBRE", "OCTUBRE", "NOVIEMBRE", "DICIEMBRE"];
const cap = s => s.charAt(0) + s.slice(1).toLowerCase();

// ---------------------------------------------------------------- vínculo
const V = {
  leer() { try { return JSON.parse(localStorage.getItem("jasan.vinculo") || "null"); } catch { return null; } },
  guardar(v) { try { localStorage.setItem("jasan.vinculo", JSON.stringify(v)); } catch {} },
  borrar() { try { localStorage.removeItem("jasan.vinculo"); } catch {} },
  deEnlace(texto) {
    texto = String(texto || "").trim();
    let j = null;
    const viejo = texto.match(/#j=([A-Za-z0-9_\-]+)/);
    if (viejo) { try { j = JSON.parse(dec.decode(b64uDec(viejo[1]))); } catch { return null; } }
    else {
      const frag = texto.includes("#") ? texto.slice(texto.indexOf("#") + 1) : texto;
      const p = new URLSearchParams(frag);
      if (!p.get("t")) return null;
      let u = p.get("u") || "";
      if (u && !/^https?:\/\//.test(u)) u = `https://${u}.supabase.co`;
      j = { v: +(p.get("v") || 1), t: p.get("t"), u, k: p.get("k") || "", id: p.get("i") || "", n: p.get("n") || "", r: p.get("r") || "" };
    }
    if (!j || !j.t || !j.u || !j.k) return null;
    j.u = j.u.replace(/\/+$/, "");
    return { ...j, desde: new Date().toISOString() };
  }
};
let vin = null, CAJA = "", KEY = null;
async function preparar(v) {
  vin = v; CAJA = hex(await sha("jasan-movil|" + v.t)).slice(0, 32);
  KEY = await crypto.subtle.importKey("raw", await sha("jasan-movil-k|" + v.t), "AES-GCM", false, ["encrypt", "decrypt"]);
}

// ---------------------------------------------------------------- cifrado
async function cifrar(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, KEY, enc.encode(JSON.stringify(obj))));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
}
async function descifrar(buf) {
  const u = new Uint8Array(buf); if (u.length < 28) throw new Error("incompleto");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.subarray(0, 12) }, KEY, u.subarray(12));
  return JSON.parse(dec.decode(pt));
}

// ---------------------------------------------------------------- nube (Supabase Storage con la clave pública)
const Nube = {
  h(extra = {}) { return { apikey: vin.k, Authorization: "Bearer " + vin.k, ...extra }; },
  q: p => p.split("/").map(encodeURIComponent).join("/"),
  async get(p) {
    const r = await fetch(`${vin.u}/storage/v1/object/authenticated/${BUCKET}/${this.q(p)}?t=${Date.now()}`, { headers: this.h(), cache: "no-store" });
    if (r.status === 400 || r.status === 404) return null;
    if (!r.ok) throw new Error("nube " + r.status);
    return await r.arrayBuffer();
  },
  async put(p, data) {
    const r = await fetch(`${vin.u}/storage/v1/object/${BUCKET}/${this.q(p)}`, { method: "POST", body: data,
      headers: this.h({ "Content-Type": "application/octet-stream", "x-upsert": "true", "cache-control": "no-cache" }) });
    if (!r.ok) throw new Error(r.status === 403 || r.status === 401 ? "permiso" : "nube " + r.status);
  },
  async list(prefix) {
    const r = await fetch(`${vin.u}/storage/v1/object/list/${BUCKET}`, { method: "POST", cache: "no-store",
      headers: this.h({ "Content-Type": "application/json" }),
      body: JSON.stringify({ prefix, limit: 200, offset: 0, sortBy: { column: "name", order: "asc" } }) });
    if (!r.ok) throw new Error("nube " + r.status);
    return (await r.json()).filter(x => x.id || x.metadata);
  },
  async remove(paths) {
    if (!paths.length) return;
    await fetch(`${vin.u}/storage/v1/object/${BUCKET}`, { method: "DELETE", headers: this.h({ "Content-Type": "application/json" }),
      body: JSON.stringify({ prefixes: paths }) });
  }
};
const ruta = (sub = "") => `movil/${CAJA}` + (sub ? "/" + sub : "");

// ---------------------------------------------------------------- resultados guardados en el celular (IndexedDB)
const DB = {
  db: null,
  abrir() { return this.db || (this.db = new Promise((ok, mal) => { const r = indexedDB.open("jasan-movil", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("res", { keyPath: "id" }); r.onsuccess = () => ok(r.result); r.onerror = () => mal(r.error); })); },
  async tx(modo, fn) { const db = await this.abrir(); return new Promise((ok, mal) => { const t = db.transaction("res", modo), s = t.objectStore("res");
    const r = fn(s); t.oncomplete = () => ok(r && r.result); t.onerror = () => mal(t.error); }); },
  todos() { return this.tx("readonly", s => s.getAll()).then(x => x || []).catch(() => []); },
  poner(o) { return this.tx("readwrite", s => s.put(o)).catch(() => {}); },
  quitar(id) { return this.tx("readwrite", s => s.delete(id)).catch(() => {}); },
  vaciar() { return this.tx("readwrite", s => s.clear()).catch(() => {}); }
};

// ---------------------------------------------------------------- pantalla
const UI = {
  pila: [], actual: "",
  ver(id, { tab = true, empujar = false } = {}) {
    if (empujar && this.actual) this.pila.push(this.actual); else if (!empujar) this.pila = [];
    $$(".view").forEach(v => v.classList.toggle("on", v.id === "v-" + id));
    this.actual = id; window.scrollTo(0, 0);
    $("#tabs").classList.toggle("hide", !tab);
    $$("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === id || (id === "cuadro" && b.dataset.tab === "inicio")));
    if (id === "resultados") pintarResultados();
    if (id === "ajustes") pintarAjustes();
  },
  atras() { this.ver(this.pila.pop() || "inicio"); },
  toast(t, ms = 2400) { const el = $("#toast"); el.textContent = t; el.classList.add("on"); clearTimeout(this._t); this._t = setTimeout(() => el.classList.remove("on"), ms); },
  hoja({ icono = "i-pc", color = "#2563EB", titulo, texto, botones = [{ t: "Entendido" }] }) {
    $("#sh-ic").style.background = color; $("#sh-ic").innerHTML = `<svg><use href="#${icono}"/></svg>`;
    $("#sh-t").textContent = titulo; $("#sh-p").textContent = texto;
    const cont = $("#sh-b"); cont.innerHTML = "";
    botones.forEach((b, i) => { const x = document.createElement("button"); x.className = "btn" + (b.clase ? " " + b.clase : i ? " gray" : "");
      if (i) x.style.marginTop = "10px"; x.textContent = b.t; x.onclick = () => { UI.cerrarHoja(); b.fn && b.fn(); }; cont.appendChild(x); });
    $("#scrim").classList.add("on"); $("#sheet").classList.add("on");
  },
  cerrarHoja() { $("#scrim").classList.remove("on"); $("#sheet").classList.remove("on"); }
};
$("#scrim").onclick = () => UI.cerrarHoja();
addEventListener("scroll", () => $$(".view.on .top").forEach(t => t.classList.toggle("scrolled", scrollY > 30)), { passive: true });

// ---------------------------------------------------------------- actividades (lo que se puede desde el celular)
const ACT = {
  cel: [
    ["cuadro", "Cuadro de requerimientos", "Analítico → cuadro, desagregado y PDF", "i-grid", "#2563EB", true],
    ["cotiz", "Cotizaciones", "Llenas los datos, tu PC arma el cuadro comparativo", "i-quote", "#0EA5E9"],
    ["cartas", "Cartas con fotos", "Toma las fotos con la cámara", "i-mail", "#14B8A6"],
    ["req", "Requerimientos", "Bienes y servicios", "i-list", "#6366F1"],
    ["tdr", "TDR y EETT", "Términos de referencia y especificaciones", "i-book", "#8B5CF6"],
    ["valor", "Informe de valorización", "Con los avances que registras", "i-chart", "#F59E0B"],
    ["conf", "Conformidad", "Los datos desde el celular, la firma en la PC", "i-check", "#22A653"]
  ],
  solo: [
    ["chat", "Chat", "Con tu equipo de JASAN", "i-chat", "#34C759"],
    ["ia", "Consultar a la IA", "Criterios, normas, precios", "i-spark", "#AF52DE"],
    ["avisos", "Avisos", "Lo que publica tu administrador", "i-bell", "#FF9500"]
  ],
  pc: [
    ["pdf", "Editor de PDF", "", "i-pdf", "#E5484D"],
    ["cuadrar", "Cuadrar al monto", "", "i-scale", "#2563EB"],
    ["word", "Llenar el Word abierto", "", "i-word", "#2B579A"],
    ["firmar", "Firmar en lote", "", "i-pen", "#111827"],
    ["macros", "Mis macros y ajustes", "", "i-gear", "#8E8E93"]
  ]
};
function fila([id, t, s, ic, col, activo], modo) {
  const b = document.createElement("button"); b.className = "row" + (activo ? "" : " dim");
  const der = activo ? `<svg class="chev"><use href="#i-chev"/></svg>` : `<span class="tag${modo === "pc" ? "" : " b"}">${modo === "pc" ? "En la PC" : "Próximamente"}</span>`;
  b.innerHTML = `<span class="ic" style="background:${col}"><svg><use href="#${ic}"/></svg></span><span class="tx"><b>${esc(t)}</b>${s ? `<span>${esc(s)}</span>` : ""}</span>${der}`;
  b.onclick = () => {
    if (activo) return abrirActividad(id);
    if (modo === "pc") return UI.hoja({ icono: "i-pc", color: col, titulo: "Ábrelo en la computadora",
      texto: `«${t}» necesita la pantalla grande. Ábrelo en JASAN de tu computadora.` });
    UI.hoja({ icono: ic, color: col, titulo: t, texto: "Muy pronto también desde el celular. Por ahora, hazlo en JASAN de tu computadora." });
  };
  return b;
}
function pintarActividades() {
  for (const [k, cont] of [["cel", "#l-cel"], ["solo", "#l-solo"], ["pc", "#l-pc"]]) {
    const el = $(cont); el.innerHTML = ""; ACT[k].forEach(a => el.appendChild(fila(a, k)));
  }
}
function abrirActividad(id) { if (id === "cuadro") UI.ver("cuadro", { tab: false, empujar: true }); }
document.addEventListener("click", e => {
  const t = e.target.closest("[data-ir]"); if (t) abrirActividad(t.dataset.ir);
  if (e.target.closest("[data-atras]")) UI.atras();
  const tb = e.target.closest("[data-tab]"); if (tb) UI.ver(tb.dataset.tab);
});

// ---------------------------------------------------------------- estado de la PC
let pcVivo = null;
async function revisarPC() {
  if (!vin) return;
  try {
    if (await Nube.get(ruta("anulado"))) return desvinculado();
    const b = await Nube.get(ruta("pc.bin"));
    const pc = b ? await descifrar(b) : null;
    const vivo = pc && (Date.now() - new Date(pc.visto).getTime()) / 1000 < VIVO_SEG;
    pcVivo = !!vivo;
    $("#pc").classList.toggle("on", !!vivo);
    $("#pc-t").textContent = vivo ? `Tu PC está lista${pc.pc ? " · " + pc.pc : ""}` : "Tu PC no está conectada";
    $("#pc-s").textContent = vivo ? "Lo que envíes se hace ahora mismo" :
      pc ? `Vista ${hace(pc.visto)}. Abre JASAN y lo hará al conectarse.` : "Abre JASAN en tu computadora. Lo hará al conectarse.";
    if (pc && pc.pc) { try { localStorage.setItem("jasan.pc", pc.pc); } catch {} }
  } catch (e) {
    $("#pc").classList.remove("on");
    $("#pc-t").textContent = navigator.onLine ? "No se pudo consultar" : "Sin internet";
    $("#pc-s").textContent = navigator.onLine ? "Se vuelve a intentar en unos segundos" : "Revisa tu conexión";
  }
}

// ---------------------------------------------------------------- formulario del cuadro
let xls = null;
function prepararCuadro() {
  const hoy = new Date(), mes = $("#c-mes"), anio = $("#c-anio");
  mes.innerHTML = MESES.map((m, i) => `<option value="${m}"${i === hoy.getMonth() ? " selected" : ""}>${cap(m)}</option>`).join("");
  anio.innerHTML = [-1, 0, 1].map(d => hoy.getFullYear() + d).map(y => `<option${y === hoy.getFullYear() ? " selected" : ""}>${y}</option>`).join("");
  let desde = 1; const out = $("#c-desde");
  $("#n-menos").onclick = () => { desde = Math.max(1, desde - 1); out.textContent = desde; };
  $("#n-mas").onclick = () => { desde = Math.min(999, desde + 1); out.textContent = desde; };
  try { const g = JSON.parse(localStorage.getItem("jasan.cuadro") || "{}");
    if (g.just) $("#c-just").value = g.just; if ("sup" in g) $("#c-sup").checked = g.sup; if ("res" in g) $("#c-res").checked = g.res; } catch {}
  const elegir = () => $("#f-xls").click();
  $("#b-xls").onclick = elegir; $("#b-xls2").onclick = elegir;
  $("#f-xls").onchange = e => {
    const f = e.target.files[0]; e.target.value = ""; if (!f) return;
    if (!/\.(xlsx|xlsm)$/i.test(f.name)) return UI.hoja({ icono: "i-grid", color: "#E5484D", titulo: "Ese no es un Excel", texto: "Elige el analítico o el desagregado en formato .xlsx." });
    if (f.size > TOPE_MB * 1048576) return UI.hoja({ icono: "i-grid", color: "#E5484D", titulo: "Archivo muy pesado", texto: `El Excel pasa los ${TOPE_MB} MB.` });
    xls = f; $("#xls-n").textContent = f.name; $("#xls-t").textContent = tam(f.size) + " · listo para enviar";
    $("#b-xls").classList.add("hide"); $("#xls-ok").classList.remove("hide");
  };
  $("#b-enviar").onclick = enviarCuadro;
}
async function enviarCuadro() {
  const just = $("#c-just").value.trim();
  if (!xls) return UI.toast("Primero elige el Excel");
  if (!just) { $("#c-just").focus(); return UI.toast("Escribe la justificación"); }
  const btn = $("#b-enviar"); btn.disabled = true; btn.innerHTML = `<i class="spin"></i>Enviando…`;
  try {
    const b64 = b64Enc(new Uint8Array(await xls.arrayBuffer()));
    const id = nuevoId(), creado = isoLocal();
    const datos = { fecha: `${$("#c-mes").value} ${$("#c-anio").value}`, justificacion: just, desde: +$("#c-desde").textContent,
      supervisor: $("#c-sup").checked, residente: $("#c-res").checked };
    const ped = { tipo: "cuadro", creado, datos, pdf: $("#c-pdf").checked, archivos: [{ nombre: xls.name, b64 }] };
    await Nube.put(ruta(`pedidos/${id}.bin`), await cifrar(ped));
    try { localStorage.setItem("jasan.cuadro", JSON.stringify({ just, sup: datos.supervisor, res: datos.residente })); } catch {}
    await DB.poner({ id, estado: "espera", titulo: "Cuadro de requerimientos", resumen: xls.name, tipo: "cuadro", pedido: creado, archivos: [] });
    xls = null; $("#b-xls").classList.remove("hide"); $("#xls-ok").classList.add("hide");
    UI.ver("resultados");
    UI.toast(pcVivo ? "Enviado. Tu PC ya lo está haciendo" : "Enviado. Tu PC lo hará al conectarse", 3200);
    vigilar(true);
  } catch (e) {
    UI.hoja({ icono: "i-up", color: "#E5484D", titulo: "No se pudo enviar",
      texto: String(e.message) === "permiso" ? "La nube de JASAN todavía no acepta pedidos del celular. Pide a tu administrador que active JASAN Móvil (Ajustes → Nube)." :
        navigator.onLine ? "La nube no respondió. Vuelve a intentarlo en un momento." : "No tienes internet. Conéctate y vuelve a intentarlo." });
  } finally { btn.disabled = false; btn.textContent = "Enviar a mi PC"; }
}

// ---------------------------------------------------------------- resultados
let vigilando = null;
async function traerResultados() {
  if (!vin) return 0;
  let nuevos = 0;
  try {
    const lista = await Nube.list(ruta("resultados"));
    const locales = Object.fromEntries((await DB.todos()).map(x => [x.id, x]));
    for (const x of lista) {
      if (!x.name.endsWith(".bin")) continue;
      const id = x.name.slice(0, -4), p = ruta("resultados/" + x.name);
      const b = await Nube.get(p); if (!b) continue;
      let r; try { r = await descifrar(b); } catch { await Nube.remove([p]); continue; }
      const prev = locales[id] || {};
      if (r.estado === "trabajando") { if (prev.estado !== "trabajando") await DB.poner({ ...prev, id, estado: "trabajando", titulo: prev.titulo || "Cuadro de requerimientos" }); continue; }
      await DB.poner({ ...r, id, nuevo: true, recibido: new Date().toISOString() });
      await Nube.remove([p]);                         // no cargar la nube: ya está en el celular
      nuevos++;
    }
  } catch {}
  return nuevos;
}
function vigilar(rapido) {
  clearTimeout(vigilando);
  const paso = async () => {
    const n = await traerResultados();
    if (n) { UI.toast(n === 1 ? "Llegó un resultado" : `Llegaron ${n} resultados`); try { navigator.vibrate && navigator.vibrate(30); } catch {} }
    await pintarBadge(); if (UI.actual === "resultados") pintarResultados();
    const pend = (await DB.todos()).some(x => x.estado === "espera" || x.estado === "trabajando");
    vigilando = setTimeout(paso, pend ? 6000 : 30000);
  };
  vigilando = setTimeout(paso, rapido ? 2500 : 0);
}
async function pintarBadge() {
  const n = (await DB.todos()).filter(x => x.nuevo).length;
  $("#badge").textContent = n; $("#badge").classList.toggle("hide", !n);
}
const ESTADO = { listo: "Listo", observado: "Observado", error: "No se hizo", espera: "Enviado", trabajando: "Tu PC lo hace" };
function clase(nombre) { const e = nombre.split(".").pop().toLowerCase();
  return e === "pdf" ? ["pdf", "PDF"] : e === "docx" ? ["doc", "DOCX"] : e === "txt" ? ["txt", "TXT"] : ["", "XLSX"]; }
async function pintarResultados() {
  const lista = (await DB.todos()).sort((a, b) => String(b.pedido || "").localeCompare(String(a.pedido || "")));
  const cont = $("#l-res"); cont.innerHTML = "";
  if (!lista.length) {
    cont.innerHTML = `<div class="empty"><svg><use href="#i-tray"/></svg><b>Todavía no hay resultados</b>Envía un cuadro de requerimientos y aquí lo recibirás.</div>`;
    return;
  }
  for (const r of lista) {
    const el = document.createElement("div"); el.className = "res";
    const esperando = r.estado === "espera" || r.estado === "trabajando";
    const sub = esperando ? (r.estado === "espera" ? (pcVivo ? "Tu PC lo recibe en segundos…" : "Esperando a que tu PC se conecte") : "Revisando el analítico y armando el cuadro…") : r.resumen;
    el.innerHTML = `<div class="hd"><b>${esc(r.estado === "listo" || r.estado === "observado" ? (r.tipo === "cuadro" ? "Cuadro · " : "") + r.titulo : r.titulo)}</b>
      <span class="st ${r.estado}">${esperando ? '<i class="spin mini"></i>' : ""}${ESTADO[r.estado] || r.estado}</span></div>
      <div class="when">${esc(hace(r.hecho || r.pedido))}</div><p>${esc(sub)}</p>
      ${esperando ? '<div class="bar"><i></i></div>' : ""}<div class="files"></div>`;
    const fl = $(".files", el);
    (r.archivos || []).forEach((a, i) => {
      const [c, t] = clase(a.nombre); const f = document.createElement("div"); f.className = "file"; f.style.boxShadow = "none"; f.style.background = "var(--card2)";
      f.innerHTML = `<i class="xl ${c}">${t}</i><div class="tx"><b>${esc(a.nombre)}</b><span>${tam(a.tam || a.b64.length * .75)}</span></div>
        <button class="link" aria-label="Guardar"><svg width="22" height="22"><use href="#${navigator.canShare ? "i-share" : "i-down"}"/></svg></button>`;
      f.onclick = () => bajar(r, i);
      fl.appendChild(f);
    });
    if (!esperando || r.estado === "espera") {
      const q = document.createElement("button"); q.className = "link"; q.style.cssText = "color:var(--sub);font-size:13px;margin-top:6px";
      q.textContent = r.estado === "espera" ? "Cancelar envío" : "Quitar"; q.onclick = () => quitar(r); el.appendChild(q);
    }
    cont.appendChild(el);
  }
  if (lista.some(x => x.nuevo)) { for (const x of lista) if (x.nuevo) { x.nuevo = false; await DB.poner(x); } setTimeout(pintarBadge, 400); }
}
const MIME = { xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", pdf: "application/pdf",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", txt: "text/plain" };
async function bajar(r, i) {
  const a = r.archivos[i], ext = a.nombre.split(".").pop().toLowerCase();
  const file = new File([b64Dec(a.b64)], a.nombre, { type: MIME[ext] || "application/octet-stream" });
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try { await navigator.share({ files: [file], title: a.nombre }); return; } catch (e) { if (e.name === "AbortError") return; }
  }
  const url = URL.createObjectURL(file), el = document.createElement("a");
  el.href = url; el.download = a.nombre; document.body.appendChild(el); el.click(); el.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
async function quitar(r) {
  if (r.estado === "espera") { try { await Nube.remove([ruta(`pedidos/${r.id}.bin`)]); } catch {} }
  await DB.quitar(r.id); pintarResultados(); pintarBadge();
}

// ---------------------------------------------------------------- ajustes
async function pintarAjustes() {
  const n = vin.n || "Usuario"; $("#a-nom").textContent = n;
  $("#a-ini").textContent = (n.replace(/^(ing|arq|lic|dr|sr|sra)\.?\s+/i, "").trim()[0] || "J").toUpperCase();
  $("#a-rol").textContent = { admin: "Administrador", user: "Usuario" }[vin.r] || (vin.r ? cap(vin.r) : "Usuario de JASAN");
  let pc = ""; try { pc = localStorage.getItem("jasan.pc") || ""; } catch {}
  $("#a-pc").textContent = pc || "—";
  $("#a-desde").textContent = new Date(vin.desde).toLocaleDateString("es-PE", { day: "numeric", month: "short", year: "numeric" });
  $("#a-n").textContent = (await DB.todos()).length;
  $("#a-ver").textContent = VERSION;
}
$("#b-borrar").onclick = () => UI.hoja({ icono: "i-tray", color: "#8E8E93", titulo: "¿Borrar los resultados?", texto: "Se quitan de este celular. Las copias en SALIDAS de tu computadora se quedan.",
  botones: [{ t: "Borrar", clase: "red", fn: async () => { await DB.vaciar(); pintarAjustes(); pintarBadge(); UI.toast("Resultados borrados"); } }, { t: "Cancelar" }] });
$("#b-desv").onclick = () => UI.hoja({ icono: "i-link", color: "#E5484D", titulo: "¿Desvincular este celular?",
  texto: "Para volver a usarlo tendrás que escanear otra vez tu QR en JASAN. Para anularlo del todo, quítalo también en la computadora.",
  botones: [{ t: "Desvincular", clase: "red", fn: async () => { V.borrar(); await DB.vaciar(); location.replace(location.pathname); } }, { t: "Cancelar" }] });
async function desvinculado() {
  V.borrar(); await DB.vaciar(); vin = null; clearTimeout(vigilando);
  UI.ver("vincular", { tab: false });
  UI.hoja({ icono: "i-lock", color: "#E5484D", titulo: "Este celular fue desvinculado", texto: "Se quitó desde JASAN en la computadora. Escanea otra vez tu QR para vincularlo." });
}

// ---------------------------------------------------------------- instalar
let promptInstalar = null;
addEventListener("beforeinstallprompt", e => { e.preventDefault(); promptInstalar = e; $("#ins-android").classList.remove("hide"); $("#ins-otro").classList.add("hide"); });
const standalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
const esIOS = () => /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
function pantallaInstalar() {
  $("#ins-hola").textContent = `¡Hola, ${primerNombre()}!`;
  $("#ins-ios").classList.toggle("hide", !esIOS());
  $("#ins-android").classList.toggle("hide", !promptInstalar);
  $("#ins-otro").classList.toggle("hide", esIOS() || !!promptInstalar);
  UI.ver("instalar", { tab: false });
}
$("#b-instalar").onclick = async () => { if (!promptInstalar) return; promptInstalar.prompt(); const r = await promptInstalar.userChoice; promptInstalar = null;
  if (r.outcome === "accepted") { UI.toast("JASAN se agregó a tu inicio"); entrar(); } };
$("#b-seguir").onclick = () => { try { sessionStorage.setItem("jasan.seguir", "1"); } catch {} entrar(); };
addEventListener("appinstalled", () => entrar());

// ---------------------------------------------------------------- arranque
function primerNombre() { const n = (vin && vin.n || "").replace(/^(ing|arq|lic|dr|sr|sra)\.?\s+/i, "").trim(); return n.split(/\s+/)[0] || "de nuevo"; }
function entrar() {
  const h = new Date().getHours();
  $("#hola").textContent = `${h < 12 ? "Buenos días" : h < 19 ? "Buenas tardes" : "Buenas noches"}, ${primerNombre()}`;
  const f = new Date().toLocaleDateString("es-PE", { weekday: "long", day: "numeric", month: "long" });
  $("#hoy").textContent = f.charAt(0).toUpperCase() + f.slice(1);
  UI.ver("inicio"); revisarPC(); vigilar(false);
  clearInterval(entrar._t); entrar._t = setInterval(() => { if (!document.hidden) revisarPC(); }, 20000);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden && vin) { revisarPC(); vigilar(false); } });
$("#b-pegar").onclick = async () => {
  const v = V.deEnlace($("#pegar").value);
  if (!v) return UI.hoja({ icono: "i-link", color: "#E5484D", titulo: "Ese enlace no sirve", texto: "Copia el enlace completo desde JASAN → tu nombre → JASAN Móvil → Copiar enlace." });
  V.guardar(v); await preparar(v); entrar();
};

async function iniciar() {
  pintarActividades(); prepararCuadro();
  const t0 = Date.now();
  const delEnlace = V.deEnlace(location.hash);
  let v = V.leer();
  if (delEnlace && (!v || v.t !== delEnlace.t)) { v = delEnlace; V.guardar(v); }
  if (v) await preparar(v);
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  const espera = Math.max(0, 1900 - (Date.now() - t0));
  setTimeout(() => {
    $("#splash").classList.add("out");
    let seguir = false; try { seguir = sessionStorage.getItem("jasan.seguir") === "1"; } catch {}
    if (!v) UI.ver("vincular", { tab: false });
    else if (delEnlace && !standalone() && !seguir) pantallaInstalar();
    else entrar();
  }, espera);
}
if (!window.crypto || !crypto.subtle) {
  document.body.innerHTML = '<p style="padding:40px;text-align:center;font-family:sans-serif">Abre JASAN Móvil desde su enlace https:// en un navegador actualizado.</p>';
} else iniciar();
