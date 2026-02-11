import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

// Configuración de rutas para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

app.set('trust proxy', 1);
// --- CAPA 1: SEGURIDAD DEL SERVIDOR ---

// 1. Helmet: Oculta la tecnología (X-Powered-By) y establece CSP estricto
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"], // Permite Bootstrap
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:"],
    },
  },
}));

// 2. Rate Limiting: Limita a 100 peticiones por 15 minutos por IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Demasiadas peticiones desde esta IP, por favor intente de nuevo en 15 minutos."
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10kb' })); // Previene DoS por payload grande

// Limitador estricto para crear/editar/borrar
const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // Ventana de 1 minuto
  max: 5, // Solo 5 peticiones por IP por minuto
  message: { error: "⛔ Demasiados intentos. Espera 1 minuto." },
  standardHeaders: true, // Retorna info de límites en los headers `RateLimit-*`
  legacyHeaders: false,
  // Esta función clave extrae la IP real a través de los proxies de Cloudflare/Railway
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip;
  }
});

// Solo permitimos peticiones del mismo origen en producción
if (process.env.NODE_ENV === 'production') {
  app.use(cors({ origin: 'SAMEORIGIN' }));
} else {
  app.use(cors());
}

// --- CAPA 2: BASE DE DATOS (SQLite en Memoria/Archivo) ---
// Usamos un archivo para persistencia básica, o ':memory:' para volátil total.
const db = new sqlite3.Database('secure_db.sqlite', (err) => {
  if (err) console.error(err.message);
  console.log('Conectado a la base de datos segura.');
});

db.serialize(() => {
  // Crear tabla si no existe
  db.run(`CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL
  )`);
});

// --- CAPA 3: VALIDACIÓN Y LÓGICA (Whitelisting) ---

// Middleware de validación estricta (Solo alfanuméricos y espacios básicos)
const validateInput = (req, res, next) => {
  const { content } = req.body;
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: "Datos inválidos" });
  }

  // Regex: Permite letras, números, espacios, puntos y comas. RECHAZA < > ; " '
  // Esto elimina la posibilidad de XSS almacenado y SQLi complejo.
  const regexSeguro = /^[a-zA-Z0-9\s.,?!áéíóúÁÉÍÓÚñÑ]+$/;

  if (!regexSeguro.test(content)) {
    return res.status(400).json({ error: "Caracteres no permitidos detectados." });
  }
  next();
};

// --- API RESTFUL ---

// GET: Obtener todos
app.get('/api/secrets', (req, res) => {
  db.all("SELECT id, content FROM secrets ORDER BY id DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error interno del servidor" });
    res.json(rows);
  });
});

// POST: Crear (Protegido)
app.post('/api/secrets', strictLimiter, validateInput, (req, res) => {
  const { content } = req.body;
  // USO DE PREPARED STATEMENT (?) -> Imposible inyectar SQL

  const stmt = db.prepare("INSERT INTO secrets (content) VALUES (?)");
  stmt.run(content, function (err) {
    if (err) return res.status(500).json({ error: "Error al guardar" });
    res.status(201).json({ id: this.lastID, content });
  });
  stmt.finalize();
});

// PUT: Editar (Protegido)
app.put('/api/secrets/:id', strictLimiter, validateInput, (req, res) => {
  const { content } = req.body;
  const { id } = req.params;

  // Validar que ID sea número
  if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const stmt = db.prepare("UPDATE secrets SET content = ? WHERE id = ?");
  stmt.run(content, id, function (err) {
    if (err) return res.status(500).json({ error: "Error al actualizar" });
    if (this.changes === 0) return res.status(404).json({ error: "Registro no encontrado" });
    res.json({ message: "Actualizado correctamente" });
  });
  stmt.finalize();
});

// DELETE: Eliminar
app.delete('/api/secrets/:id',  (req, res) => {
  const { id } = req.params;
  if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });

  const stmt = db.prepare("DELETE FROM secrets WHERE id = ?");
  stmt.run(id, function (err) {
    if (err) return res.status(500).json({ error: "Error al eliminar" });
    res.json({ message: "Eliminado correctamente" });
  });
  stmt.finalize();
});

// --- SERVIR FRONTEND EN PRODUCCIÓN ---
// Esto permite que Node sirva los archivos estáticos de React
app.use(express.static(path.join(__dirname, '../dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor seguro corriendo en puerto ${PORT}`);
});