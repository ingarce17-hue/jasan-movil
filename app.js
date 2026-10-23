/* JASAN Móvil · el celular arma el pedido, lo cifra y lo deja en el buzón; la PC del mismo usuario lo hace.
   Protocolo (igual a app/movil.py de JASAN):
     enlace  …/#j=<b64url JSON {v,u,k,t,id,n,r}>
     caja    = sha256("jasan-movil|"+t) en hex, 32 primeros
     clave   = sha256("jasan-movil-k|"+t) → AES-256-GCM; blob = nonce12 | cifrado | tag16
     rutas   movil/<caja>/pedidos/<id>.bin · resultados/<id>.bin · pc.bin · anulado            */
"use strict";
const VERSION = "1.4 (JASAN 2.40.1)";
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
async function descifrarBytes(buf) {
  const u = new Uint8Array(buf); if (u.length < 28) throw new Error("incompleto");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.subarray(0, 12) }, KEY, u.subarray(12)));
}
async function descifrar(buf) { return JSON.parse(dec.decode(await descifrarBytes(buf))); }

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
  abrir() { return this.db || (this.db = new Promise((ok, mal) => { const r = indexedDB.open("jasan-movil", 2);
    r.onupgradeneeded = () => { const db = r.result;
      if (!db.objectStoreNames.contains("res")) db.createObjectStore("res", { keyPath: "id" });
      if (!db.objectStoreNames.contains("arch")) db.createObjectStore("arch", { keyPath: "id" }); };
    r.onsuccess = () => ok(r.result); r.onerror = () => mal(r.error); })); },
  async tx(modo, fn, tienda = "res") { const db = await this.abrir(); return new Promise((ok, mal) => { const t = db.transaction(tienda, modo), s = t.objectStore(tienda);
    const r = fn(s); t.oncomplete = () => ok(r && r.result); t.onerror = () => mal(t.error); }); },
  todos() { return this.tx("readonly", s => s.getAll()).then(x => x || []).catch(() => []); },
  poner(o) { return this.tx("readwrite", s => s.put(o)).catch(() => {}); },
  quitar(id) { return this.tx("readwrite", s => s.delete(id)).catch(() => {}); },
  vaciar() { return Promise.all([this.tx("readwrite", s => s.clear()), this.tx("readwrite", s => s.clear(), "arch")]).catch(() => {}); },
  arch(id) { return this.tx("readonly", s => s.get(id), "arch").catch(() => null); },
  guardarArch(o) { return this.tx("readwrite", s => s.put(o), "arch").catch(() => {}); },
  archivos() { return this.tx("readonly", s => s.getAll(), "arch").then(x => x || []).catch(() => []); },
  quitarArch(id) { return this.tx("readwrite", s => s.delete(id), "arch").catch(() => {}); }
};

// ---------------------------------------------------------------- pantalla
const UI = {
  pila: [], actual: "",
  ver(id, { tab = true, empujar = false } = {}) {
    if (empujar && this.actual) this.pila.push(this.actual); else if (!empujar) this.pila = [];
    $$(".view").forEach(v => v.classList.toggle("on", v.id === "v-" + id));
    this.actual = id; window.scrollTo(0, 0);
    $("#tabs").classList.toggle("hide", !tab);
    $$("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === id || (["cuadro", "req", "cotiz", "enviar"].includes(id) && b.dataset.tab === "inicio")));
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
    ["enviar", "A mi PC", "Fotos o archivos del celular a tu computadora", "i-pc", "#0A84FF", true, "A mi PC"],
    ["cuadro", "Cuadro de requerimientos", "Analítico → cuadro, desagregado y PDF", "i-grid", "#2563EB", true, "Cuadro de req."],
    ["cotiz", "Cotizaciones", "Excel del cuadro → los 8 PDF de cada proceso", "i-quote", "#0EA5E9", true, "Cotizaciones"],
    ["cartas", "Cartas con fotos", "Toma las fotos con la cámara", "i-mail", "#14B8A6", false, "Cartas"],
    ["req", "Requerimientos", "Cuadro → una carta por pestaña", "i-list", "#6366F1", true, "Requerim."],
    ["tdr", "TDR y EETT", "Términos de referencia y especificaciones", "i-book", "#8B5CF6", false, "TDR y EETT"],
    ["valor", "Informe de valorización", "Con los avances que registras", "i-chart", "#F59E0B", false, "Valorización"],
    ["conf", "Conformidad", "Los datos desde el celular, la firma en la PC", "i-check", "#22A653", false, "Conformidad"]
  ],
  solo: [
    ["chat", "Chat", "Con tu equipo de JASAN", "i-chat", "#34C759", false, "Chat"],
    ["ia", "Consultar a la IA", "Criterios, normas, precios", "i-spark", "#AF52DE", false, "Consultar IA"],
    ["avisos", "Avisos", "Lo que publica tu administrador", "i-bell", "#FF9500", false, "Avisos"]
  ],
  pc: [
    ["pdf", "Editor de PDF", "", "i-pdf", "#E5484D", false, "PDF"],
    ["cuadrar", "Cuadrar al monto", "", "i-scale", "#2563EB", false, "Cuadrar"],
    ["word", "Llenar el Word abierto", "", "i-word", "#2B579A", false, "Llenar Word"],
    ["firmar", "Firmar en lote", "", "i-pen", "#111827", false, "Firmar lote"],
    ["macros", "Mis macros y ajustes", "", "i-gear", "#8E8E93", false, "Macros"]
  ]
};
function fila([id, t, s, ic, col, activo, corto], modo) {
  const b = document.createElement("button"); b.className = "app" + (activo ? "" : " dim");
  const pill = activo ? "" : `<span class="pill${modo === "pc" ? "" : " b"}">${modo === "pc" ? "PC" : "Pronto"}</span>`;
  b.innerHTML = `<span class="ai" style="background:${col}"><svg><use href="#${ic}"/></svg></span>${pill}<b>${esc(corto || t)}</b>`;
  b.setAttribute("aria-label", t);
  b.onclick = () => {
    if (activo) return abrirActividad(id);
    if (modo === "pc") return UI.hoja({ icono: ic, color: col, titulo: "Ábrelo en la computadora",
      texto: `«${t}» necesita la pantalla grande. Ábrelo en JASAN de tu computadora.` });
    UI.hoja({ icono: ic, color: col, titulo: t, texto: (s ? s + ". " : "") + "Muy pronto también desde el celular; por ahora, hazlo en JASAN de tu computadora." });
  };
  return b;
}
function pintarActividades() {
  for (const [k, cont] of [["cel", "#l-cel"], ["solo", "#l-solo"], ["pc", "#l-pc"]]) {
    const el = $(cont); el.innerHTML = ""; ACT[k].forEach(a => el.appendChild(fila(a, k)));
  }
}
function abrirActividad(id) {
  const v = { cuadro: "cuadro", req: "req", cotiz: "cotiz", enviar: "enviar" }[id];
  if (!v) return;
  if (v === "req") ultimoCuadro();
  UI.ver(v, { tab: false, empujar: true });
}
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

// ---------------------------------------------------------------- envío genérico (requerimientos, cotizaciones)
const ELEG = {};                     // archivo elegido por formulario: {nombre, datos(Uint8Array), tam}
function selector(p, aviso) {
  const elegir = () => $(`#f-${p}`).click();
  $(`#b-${p}`).onclick = elegir; $(`#c-${p}`).onclick = elegir;
  $(`#f-${p}`).onchange = async e => {
    const f = e.target.files[0]; e.target.value = ""; if (!f) return;
    if (!/\.(xlsx|xlsm)$/i.test(f.name)) return UI.hoja({ icono: "i-grid", color: "#E5484D", titulo: "Ese no es un Excel", texto: aviso });
    if (f.size > TOPE_MB * 1048576) return UI.hoja({ icono: "i-grid", color: "#E5484D", titulo: "Archivo muy pesado", texto: `El Excel pasa los ${TOPE_MB} MB.` });
    ponerArchivo(p, { nombre: f.name, datos: new Uint8Array(await f.arrayBuffer()), tam: f.size });
  };
}
function ponerArchivo(p, a) {
  ELEG[p] = a;
  $(`#n-${p}`).textContent = a ? a.nombre : ""; $(`#t-${p}`).textContent = a ? tam(a.tam) + " · listo para enviar" : "";
  $(`#b-${p}`).classList.toggle("hide", !!a); $(`#ok-${p}`).classList.toggle("hide", !a);
  if (p === "req") $("#ult-req").classList.add("hide");
}
async function enviarPedido({ tipo, p, datos, titulo, boton }) {
  const a = ELEG[p];
  if (!a) return UI.toast("Primero elige el Excel");
  const btn = $(boton); btn.disabled = true; btn.innerHTML = `<i class="spin"></i>Enviando…`;
  try {
    const id = nuevoId(), creado = isoLocal();
    const ped = { tipo, creado, datos, archivos: [{ nombre: a.nombre, b64: b64Enc(a.datos) }] };
    await Nube.put(ruta(`pedidos/${id}.bin`), await cifrar(ped));
    await DB.poner({ id, estado: "espera", titulo, resumen: a.nombre, tipo, pedido: creado, archivos: [] });
    ponerArchivo(p, null);
    UI.ver("resultados"); verPanel("cel");
    UI.toast(pcVivo ? "Enviado. Tu PC ya lo está haciendo" : "Enviado. Tu PC lo hará al conectarse", 3200);
    vigilar(true);
  } catch (e) {
    UI.hoja({ icono: "i-up", color: "#E5484D", titulo: "No se pudo enviar",
      texto: String(e.message) === "permiso" ? "La nube de JASAN todavía no acepta pedidos del celular. Pide a tu administrador que active JASAN Móvil." :
        navigator.onLine ? "La nube no respondió. Vuelve a intentarlo en un momento." : "No tienes internet. Conéctate y vuelve a intentarlo." });
  } finally { btn.disabled = false; btn.textContent = "Enviar a mi PC"; }
}
const fechaDMY = v => { const m = String(v || "").match(/^(\d{4})-(\d{2})-(\d{2})$/); return m ? `${m[3]}/${m[2]}/${m[1]}` : ""; };
const hoyISO = () => { const d = new Date(), p = n => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; };
const recordar = (k, o) => ponerLS("jasan." + k, JSON.stringify(o));
const recordado = k => { try { return JSON.parse(leerLS("jasan." + k, "{}")) || {}; } catch { return {}; } };

// ----- Requerimientos
function prepararReq() {
  selector("req", "Elige el cuadro de requerimientos en formato .xlsx.");
  $("#r-fecha").value = hoyISO();
  const g = recordado("req"); if (g.obra) $("#r-obra").value = g.obra;
  $("#ult-req").onclick = async () => { const u = await cuadroReciente(); if (u) ponerArchivo("req", u); };
  $("#e-req").onclick = () => {
    const datos = { fecha: fechaDMY($("#r-fecha").value), obra: $("#r-obra").value.trim(),
      n_cons: $("#r-cons").value.trim(), n_sup: $("#r-sup").value.trim(), n_res: $("#r-res").value.trim() };
    const nums = [datos.n_cons, datos.n_sup, datos.n_res].filter(Boolean).length;
    if (nums && nums < 3) return UI.toast("Escribe los 3 números o deja los 3 vacíos");
    recordar("req", { obra: datos.obra });
    enviarPedido({ tipo: "requerimientos", p: "req", datos, titulo: "Requerimientos", boton: "#e-req" });
    $("#r-cons").value = $("#r-sup").value = $("#r-res").value = "";
  };
}
async function cuadroReciente() {
  const l = (await DB.todos()).filter(r => r.tipo === "cuadro" && r.estado === "listo")
    .sort((a, b) => String(b.pedido).localeCompare(String(a.pedido)));
  for (const r of l) {
    const a = (r.archivos || []).find(x => /^CUADRO DE REQUERIMIENTOS.*\.xlsx$/i.test(x.nombre));
    if (a) { const d = b64Dec(a.b64); return { nombre: a.nombre, datos: d, tam: d.length }; }
  }
  return null;
}
async function ultimoCuadro() {
  if (ELEG.req) return;
  const u = await cuadroReciente();
  $("#ult-req").classList.toggle("hide", !u);
  if (u) $("#ult-req-n").textContent = u.nombre;
}

// ----- Cotizaciones
function prepararCotiz() {
  selector("cot", "Elige el Excel de cotizaciones en formato .xlsx.");
  const hoy = new Date();
  $("#k-sol").value = hoyISO();
  $("#k-mes").innerHTML = MESES.map((m, i) => `<option value="${i + 1}"${i === hoy.getMonth() ? " selected" : ""}>${cap(m)}</option>`).join("");
  $("#k-anio").innerHTML = [-1, 0, 1].map(d => hoy.getFullYear() + d).map(y => `<option${y === hoy.getFullYear() ? " selected" : ""}>${y}</option>`).join("");
  const g = recordado("cotiz"); if (g.obra) $("#k-obra").value = g.obra; if (g.cui) $("#k-cui").value = g.cui;
  $("#e-cot").onclick = () => {
    const datos = { obra: $("#k-obra").value.trim(), cui: $("#k-cui").value.replace(/\D/g, ""), fecha_sol: fechaDMY($("#k-sol").value),
      mes: +$("#k-mes").value, anio: +$("#k-anio").value, profesionales: $("#k-prof").checked };
    recordar("cotiz", { obra: datos.obra, cui: datos.cui });
    enviarPedido({ tipo: "cotizaciones", p: "cot", datos, titulo: "Cotizaciones", boton: "#e-cot" });
  };
}

// ----- A mi PC (fotos y archivos)
const ENV = [];
const TOPE_ENV = 10 * 1048576;
function prepararEnviar() {
  $("#b-foto").onclick = () => $("#f-foto").click();
  $("#b-env").onclick = () => $("#f-env").click();
  const agregar = async e => {
    for (const f of [...e.target.files]) ENV.push({ nombre: f.name || `FOTO ${isoLocal().slice(0, 19).replace(/[T:]/g, "-")}.jpg`, datos: new Uint8Array(await f.arrayBuffer()), tam: f.size });
    e.target.value = ""; pintarEnviar();
  };
  $("#f-env").onchange = agregar; $("#f-foto").onchange = agregar;
  $("#e-env").onclick = enviarArchivos;
}
function pintarEnviar() {
  const cont = $("#l-env"); cont.innerHTML = "";
  ENV.forEach((a, i) => {
    const [c, t] = clase(a.nombre), f = document.createElement("div"); f.className = "file";
    f.innerHTML = `<i class="xl ${c}">${t}</i><div class="tx"><b>${esc(a.nombre)}</b><span>${tam(a.tam)}</span></div><button class="link" style="color:var(--red)">Quitar</button>`;
    f.querySelector("button").onclick = () => { ENV.splice(i, 1); pintarEnviar(); };
    cont.appendChild(f);
  });
  const total = ENV.reduce((s, a) => s + a.tam, 0);
  $("#tot-env").textContent = ENV.length ? `${ENV.length} archivo(s) · ${tam(total)}` + (total > TOPE_ENV ? " · pasa los 10 MB: quita alguno" : "") : "";
  $("#tot-env").style.color = total > TOPE_ENV ? "var(--red)" : "";
}
async function enviarArchivos() {
  if (!ENV.length) return UI.toast("Elige al menos un archivo o toma una foto");
  if (ENV.reduce((s, a) => s + a.tam, 0) > TOPE_ENV) return UI.toast("Pasa los 10 MB: quita alguno o mándalos por partes");
  const btn = $("#e-env"); btn.disabled = true; btn.innerHTML = `<i class="spin"></i>Enviando…`;
  try {
    const id = nuevoId(), creado = isoLocal();
    const ped = { tipo: "archivos", creado, datos: { nota: $("#nota-env").value.trim() }, archivos: ENV.map(a => ({ nombre: a.nombre, b64: b64Enc(a.datos) })) };
    await Nube.put(ruta(`pedidos/${id}.bin`), await cifrar(ped));
    await DB.poner({ id, estado: "espera", titulo: "A mi PC", resumen: `${ENV.length} archivo(s)`, tipo: "archivos", pedido: creado, archivos: [] });
    ENV.length = 0; pintarEnviar(); $("#nota-env").value = "";
    UI.ver("resultados"); verPanel("cel");
    UI.toast(pcVivo ? "Enviado. Llega a tu PC en segundos" : "Enviado. Llegará cuando tu PC se conecte", 3200);
    vigilar(true);
  } catch (e) {
    UI.hoja({ icono: "i-up", color: "#E5484D", titulo: "No se pudo enviar", texto: navigator.onLine ? "La nube no respondió. Vuelve a intentarlo." : "No tienes internet." });
  } finally { btn.disabled = false; btn.textContent = "Mandar a mi PC"; }
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
      if (r.estado === "trabajando") { if (prev.estado !== "trabajando") await DB.poner({ ...prev, id, estado: "trabajando", titulo: prev.titulo || "Pedido" }); continue; }
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
    if (!document.hidden) await traerSalidas();
    await pintarBadge(); if (UI.actual === "resultados") pintarResultados();
    const pend = (await DB.todos()).some(x => x.estado === "espera" || x.estado === "trabajando");
    vigilando = setTimeout(paso, pend ? 6000 : 30000);
  };
  vigilando = setTimeout(paso, rapido ? 2500 : 0);
}
async function pintarBadge() {
  const n = (await DB.todos()).filter(x => x.nuevo).length + salNuevas();
  $("#badge").textContent = n; $("#badge").classList.toggle("hide", !n);
}
const ESTADO = { listo: "Listo", observado: "Observado", error: "No se hizo", espera: "Enviado", trabajando: "Tu PC lo hace" };
function clase(nombre) { const e = nombre.split(".").pop().toLowerCase();
  if (e === "pdf") return ["pdf", "PDF"]; if (e === "docx" || e === "doc") return ["doc", e.toUpperCase()];
  if (["txt", "csv", "zip", "jpg", "jpeg", "png", "pptx"].includes(e)) return ["txt", e.toUpperCase().slice(0, 4)];
  return ["", e.toUpperCase().slice(0, 4)]; }
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
    const haciendo = { cuadro: "Revisando el analítico y armando el cuadro…", requerimientos: "Armando las cartas con tu macro…",
      cotizaciones: "Armando los 8 PDF de cada proceso…", archivos: "Guardándolos en tu PC…" }[r.tipo] || "Tu PC lo está haciendo…";
    const sub = esperando ? (r.estado === "espera" ? (pcVivo ? "Tu PC lo recibe en segundos…" : "Esperando a que tu PC se conecte") : haciendo) : r.resumen;
    el.innerHTML = `<div class="hd"><b>${esc(r.estado === "listo" || r.estado === "observado" ? (r.tipo === "cuadro" ? "Cuadro · " : "") + r.titulo : r.titulo)}</b>
      <span class="st ${r.estado}">${esperando ? '<i class="spin mini"></i>' : ""}${ESTADO[r.estado] || r.estado}</span></div>
      <div class="when">${esc(hace(r.hecho || r.pedido))}</div><p>${esc(sub)}</p>
      ${esperando ? '<div class="bar"><i></i></div>' : ""}<div class="files"></div>`;
    const fl = $(".files", el);
    (r.archivos || []).forEach((a, i) => {
      const [c, t] = clase(a.nombre); const f = document.createElement("div"); f.className = "file"; f.style.boxShadow = "none"; f.style.background = "var(--card2)";
      f.innerHTML = `<i class="xl ${c}">${t}</i><div class="tx"><b>${esc(a.nombre)}</b><span>${tam(a.tam || a.b64.length * .75)}</span></div>
        <button class="link" aria-label="Guardar"><svg width="22" height="22"><use href="#${navigator.canShare ? "i-share" : "i-down"}"/></svg></button>`;
      f.onclick = () => acciones([archivoDe(a)]);
      fl.appendChild(f);
    });
    const pie = document.createElement("div"); pie.style.cssText = "display:flex;justify-content:space-between;align-items:center;margin-top:6px";
    if (!esperando || r.estado === "espera") {
      const q = document.createElement("button"); q.className = "link"; q.style.cssText = "color:var(--sub);font-size:13px";
      q.textContent = r.estado === "espera" ? "Cancelar envío" : "Quitar"; q.onclick = () => quitar(r); pie.appendChild(q);
    }
    if ((r.archivos || []).length > 1) {
      const c = document.createElement("button"); c.className = "link compartir-todo"; c.style.cssText = "display:flex;align-items:center;gap:5px;font-size:14px";
      c.innerHTML = `<svg width="17" height="17"><use href="#i-share"/></svg>Compartir todos (${r.archivos.length})`;
      c.onclick = () => acciones(r.archivos.map(archivoDe)); pie.appendChild(c);
    }
    el.appendChild(pie);
    if (r.tipo === "cuadro" && r.estado === "listo") {
      const h = document.createElement("button"); h.className = "btn gray"; h.style.cssText = "height:42px;font-size:15px;margin-top:10px";
      h.innerHTML = `<svg width="18" height="18"><use href="#i-list"/></svg>Hacer los requerimientos`;
      h.onclick = () => { const a = (r.archivos || []).find(x => /^CUADRO DE REQUERIMIENTOS.*\.xlsx$/i.test(x.nombre));
        if (a) { const d = b64Dec(a.b64); ponerArchivo("req", { nombre: a.nombre, datos: d, tam: d.length }); }
        UI.ver("req", { tab: false, empujar: true }); };
      el.appendChild(h);
    }
    cont.appendChild(el);
  }
  if (lista.some(x => x.nuevo)) { for (const x of lista) if (x.nuevo) { x.nuevo = false; await DB.poner(x); } setTimeout(pintarBadge, 400); }
}
const MIME = { xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", pdf: "application/pdf",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", txt: "text/plain",
  xlsm: "application/vnd.ms-excel.sheet.macroEnabled.12", xls: "application/vnd.ms-excel", doc: "application/msword", csv: "text/csv",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation", zip: "application/zip", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png" };
const hacerArchivo = (datos, nombre) => new File([datos], nombre, { type: MIME[nombre.split(".").pop().toLowerCase()] || "application/octet-stream" });
const archivoDe = a => hacerArchivo(b64Dec(a.b64), a.nombre);
const puedeCompartir = files => { try { return !!(navigator.canShare && navigator.canShare({ files })); } catch { return false; } };
/* Hoja con «Compartir» (WhatsApp, correo, Drive… del propio celular) y «Guardar en el celular».
   Los archivos ya están listos en el celular: el toque en el botón abre el menú de compartir al instante. */
function acciones(files) {
  const uno = files.length === 1, comp = puedeCompartir(files);
  UI.hoja({ icono: "i-share", color: "#25A244", titulo: uno ? files[0].name : `${files.length} archivos`,
    texto: comp ? "Envíalo por WhatsApp, correo o Drive, o guárdalo en el celular." : "Guárdalo en el celular para enviarlo luego.",
    botones: [...(comp ? [{ t: uno ? "Compartir" : `Compartir los ${files.length}`, fn: () => compartir(files) }] : []),
      { t: uno ? "Guardar en el celular" : "Guardar todos en el celular", clase: comp ? "gray" : "", fn: () => guardar(files) },
      { t: "Cancelar", clase: "gray" }] });
}
async function compartir(files) {
  try { await navigator.share({ files, title: files.length === 1 ? files[0].name : "JASAN" }); }
  catch (e) { if (e.name !== "AbortError") { UI.toast("No se pudo compartir; se guardan en el celular"); guardar(files); } }
}
function guardar(files) {
  files.forEach((file, i) => setTimeout(() => {
    const url = URL.createObjectURL(file), el = document.createElement("a");
    el.href = url; el.download = file.name; document.body.appendChild(el); el.click(); el.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }, i * 400));
}
async function quitar(r) {
  if (r.estado === "espera") { try { await Nube.remove([ruta(`pedidos/${r.id}.bin`)]); } catch {} }
  await DB.quitar(r.id); pintarResultados(); pintarBadge();
}

// ---------------------------------------------------------------- salidas de la PC (7 días en la nube)
let SAL = [], salTraido = false, panelRes = "cel";
const leerLS = (k, d = "") => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const ponerLS = (k, v) => { try { localStorage.setItem(k, v); } catch {} };
function salNuevas() { const v = leerLS("jasan.salvisto"); return SAL.filter(x => (x.subido || "") > v).length; }
async function traerSalidas() {
  if (!vin) return;
  try { const b = await Nube.get(ruta("salidas.bin")); SAL = b ? ((await descifrar(b)).archivos || []) : []; salTraido = true; } catch {}
  const vivos = new Set(SAL.map(x => x.id));                 // lo que la PC ya borró, también sale del celular
  for (const a of await DB.archivos()) if (!vivos.has(a.id) && salTraido) await DB.quitarArch(a.id);
  $("#dot-pc").classList.toggle("hide", !salNuevas());
}
$$("#seg-res button").forEach(b => b.onclick = () => verPanel(b.dataset.s));
function verPanel(p) {
  panelRes = p;
  $$("#seg-res button").forEach(b => b.classList.toggle("on", b.dataset.s === p));
  $("#p-cel").classList.toggle("hide", p !== "cel"); $("#p-pc").classList.toggle("hide", p !== "pc");
  if (p === "pc") { pintarSalidas(); traerSalidas().then(pintarSalidas); }
}
async function pintarSalidas() {
  const cont = $("#l-sal"), guard = new Set((await DB.archivos()).map(a => a.id));
  if (!SAL.length) {
    cont.innerHTML = `<div class="empty"><svg><use href="#i-pc"/></svg><b>${salTraido ? "Nada en los últimos 7 días" : "Cargando…"}</b>${salTraido ? "Lo que generes en JASAN de tu computadora aparecerá aquí." : ""}</div>`;
    return;
  }
  const lista = [...SAL].sort((a, b) => String(b.fecha).localeCompare(String(a.fecha)));
  const visto = leerLS("jasan.salvisto");
  cont.innerHTML = "";
  let dia = "", grupo = null;
  for (const a of lista) {
    const d = new Date(a.fecha), k = d.toDateString();
    if (k !== dia) {
      dia = k; const hoy = new Date().toDateString(), ayer = new Date(Date.now() - 864e5).toDateString();
      const t = document.createElement("div"); t.className = "dia";
      t.textContent = k === hoy ? "Hoy" : k === ayer ? "Ayer" : d.toLocaleDateString("es-PE", { weekday: "long", day: "numeric", month: "long" });
      const del = lista.filter(x => new Date(x.fecha).toDateString() === k);
      t.style.cssText = "display:flex;justify-content:space-between;align-items:center";
      t.innerHTML = `<span>${t.textContent}</span>` + (del.length > 1 ? `<button class="link compartir-todo" style="text-transform:none;font-size:13.5px;display:flex;align-items:center;gap:4px"><svg width="15" height="15"><use href="#i-share"/></svg>Compartir todos (${del.length})</button>` : "");
      const bt = t.querySelector("button"); if (bt) bt.onclick = () => salidasLote(del, bt);
      cont.appendChild(t); grupo = document.createElement("div"); grupo.className = "list"; cont.appendChild(grupo);
    }
    const [c, t] = clase(a.nombre), b = document.createElement("button"); b.className = "sal";
    const nuevo = (a.subido || "") > visto;
    b.innerHTML = `<i class="xl ${c}" style="width:36px;height:44px;border-radius:7px;font-size:10.5px;font-weight:700;color:#fff;display:grid;place-items:center;flex:none;font-style:normal;background:${{ pdf: "#D93025", doc: "#2B579A", txt: "#6E6E73" }[c] || "#1D7044"}">${t}</i>
      <span class="tx"><b>${esc(a.nombre)}</b><span>${nuevo ? '<b style="display:inline;color:var(--blue);font-size:12.5px">Nuevo · </b>' : ""}${esc(a.carpeta || "SALIDAS")} · ${tam(a.tam)} · ${d.toLocaleTimeString("es-PE", { hour: "2-digit", minute: "2-digit" })}</span></span>
      <svg width="22" height="22" class="${guard.has(a.id) ? "ok" : ""}" style="flex:none;color:${guard.has(a.id) ? "var(--green)" : "var(--blue)"}"><use href="#${guard.has(a.id) ? "i-check" : "i-down"}"/></svg>`;
    b.onclick = () => bajarSalida(a, b);
    grupo.appendChild(b);
  }
  const ult = lista.reduce((m, x) => (x.subido || "") > m ? x.subido : m, "");
  if (ult > visto) { ponerLS("jasan.salvisto", ult); setTimeout(() => { $("#dot-pc").classList.add("hide"); pintarBadge(); }, 600); }
}
async function datosSalida(a) {
  const o = await DB.arch(a.id); if (o && o.datos) return o.datos;
  const b = await Nube.get(ruta(`salidas/${a.id}.bin`));
  if (!b) return null;
  const datos = await descifrarBytes(b);
  if (datos.length < 8 * 1048576) await DB.guardarArch({ id: a.id, datos, nombre: a.nombre, subido: a.subido });
  return datos;
}
const ruedita = '<i class="spin mini" style="flex:none;border-color:rgba(37,99,235,.25);border-top-color:var(--blue);width:20px;height:20px"></i>';
async function bajarSalida(a, fila) {
  const ic = fila.querySelector("svg:last-child"); if (ic) ic.outerHTML = ruedita;
  try {
    const datos = await datosSalida(a);
    if (!datos) { UI.toast("Ese archivo ya no está en la nube"); return traerSalidas().then(pintarSalidas); }
    await pintarSalidas(); acciones([hacerArchivo(datos, a.nombre)]);
  } catch { UI.toast(navigator.onLine ? "No se pudo bajar. Intenta otra vez" : "Sin internet"); pintarSalidas(); }
}
async function salidasLote(lista, bt) {
  bt.innerHTML = ruedita + "Preparando…";
  try {
    const files = [];
    for (const a of lista) { const d = await datosSalida(a); if (d) files.push(hacerArchivo(d, a.nombre)); }
    await pintarSalidas();
    if (files.length) acciones(files); else UI.toast("Ya no están en la nube");
  } catch { UI.toast(navigator.onLine ? "No se pudo bajar. Intenta otra vez" : "Sin internet"); pintarSalidas(); }
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

// ---------------------------------------------------------------- día / noche
const Tema = {
  modo() { try { return localStorage.getItem("jasan.tema") || "auto"; } catch { return "auto"; } },
  aplicar(m = this.modo()) {
    const oscuro = m === "dark" || (m === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.setAttribute("data-theme", oscuro ? "dark" : "light");
    const mc = $("#m-color"); if (mc) mc.setAttribute("content", oscuro ? "#000000" : "#F2F2F7");
    $$("#tema button").forEach(b => b.classList.toggle("on", b.dataset.t === m));
  },
  poner(m) { try { localStorage.setItem("jasan.tema", m); } catch {} this.aplicar(m); }
};
$$("#tema button").forEach(b => b.onclick = () => Tema.poner(b.dataset.t));
matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => Tema.aplicar());
Tema.aplicar();

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

let recargando = false;
async function iniciar() {
  pintarActividades(); prepararCuadro(); prepararReq(); prepararCotiz(); prepararEnviar();
  const t0 = Date.now();
  const delEnlace = V.deEnlace(location.hash);
  let v = V.leer();
  if (delEnlace && (!v || v.t !== delEnlace.t)) { v = delEnlace; V.guardar(v); }
  if (v) await preparar(v);
  if ("serviceWorker" in navigator) {
    const habia = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.register("sw.js").then(reg => {
      document.addEventListener("visibilitychange", () => { if (!document.hidden) reg.update().catch(() => {}); });
    }).catch(() => {});
    navigator.serviceWorker.addEventListener("controllerchange", () => {      // llegó una versión nueva: se recarga sola
      if (!habia || recargando) return; recargando = true;
      try { sessionStorage.setItem("jasan.actualizado", "1"); } catch {}
      location.reload();
    });
  }
  const espera = Math.max(0, 1900 - (Date.now() - t0));
  setTimeout(() => {
    $("#splash").classList.add("out");
    let seguir = false; try { seguir = sessionStorage.getItem("jasan.seguir") === "1"; } catch {}
    if (!v) UI.ver("vincular", { tab: false });
    else if (delEnlace && !standalone() && !seguir) pantallaInstalar();
    else entrar();
    let act = false; try { act = sessionStorage.getItem("jasan.actualizado") === "1"; sessionStorage.removeItem("jasan.actualizado"); } catch {}
    if (act) setTimeout(() => UI.toast(`JASAN Móvil se actualizó · ${VERSION.split(" ")[0]}`, 3200), 600);
  }, espera);
}
if (!window.crypto || !crypto.subtle) {
  document.body.innerHTML = '<p style="padding:40px;text-align:center;font-family:sans-serif">Abre JASAN Móvil desde su enlace https:// en un navegador actualizado.</p>';
} else iniciar();
