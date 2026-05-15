import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import adminRoutes from './src/server/routes/admin.js';
import { setupCronJobs } from './src/server/cron.js';
import { globalApiRateLimiter } from './src/server/middleware.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// متغيرات مطلوبة لمشروع الآدمن فقط
const requiredEnvVars = [
  'ADMIN_JWT_SECRET',
  'SUPABASE_SERVICE_ROLE_KEY',
  'VITE_SUPABASE_URL',
];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ FATAL: Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

async function startServer() {
  setupCronJobs();

  const app = express();
  const PORT = Number(process.env.PORT) || 4000;

  if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
  }

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        scriptSrcElem: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        styleSrcElem: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        imgSrc: ["'self'", "data:", "blob:", "https://i.ibb.co"],
        connectSrc: ["'self'", process.env.VITE_SUPABASE_URL!],
        workerSrc: ["'self'", "blob:"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  }));

  app.use('/api', (req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  app.use(cors({
    origin: (origin, callback) => {
      // إذا لم تُحدَّد ALLOWED_ORIGINS نسمح بالكل (مفيد على Render أثناء الإعداد)
      if (!allowedOrigins.length) return callback(null, true);
      if (!origin && process.env.NODE_ENV !== 'production') return callback(null, true);
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error(`CORS policy: origin ${origin} not allowed`));
    },
    methods: ['GET', 'POST', 'DELETE', 'PATCH'],
    allowedHeaders: ['Authorization', 'Content-Type'],
    credentials: true,
  }));

  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser());

  // FIX: HTTPS redirect معطّل — Render يتعامل مع HTTPS تلقائياً
  // تفعيله يسبب redirect loop على Render
  // if (process.env.NODE_ENV === 'production') {
  //   app.use((req, res, next) => {
  //     if (req.headers['x-forwarded-proto'] !== 'https') {
  //       return res.redirect(301, `https://${req.headers.host}${req.url}`);
  //     }
  //     next();
  //   });
  // }

  app.use('/api', globalApiRateLimiter);

  // ── API Routes (قبل static و catch-all) ──
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'admin' });
  });

  app.use('/api/admin', adminRoutes);

  // ── Frontend ──
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // server.mjs في جذر المشروع، وملفات React في dist/
    const distPath = path.join(__dirname);

    // FIX: تحديد MIME types بشكل صريح لمنع إرجاع application/json للـ assets
    app.use(express.static(distPath, {
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('.js') || filePath.endsWith('.mjs')) {
          res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        } else if (filePath.endsWith('.css')) {
          res.setHeader('Content-Type', 'text/css; charset=utf-8');
        } else if (filePath.endsWith('.html')) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
        }
      },
    }));

    // SPA fallback — فقط للمسارات التي ليست /api
    app.get('*', (req, res) => {
      if (req.path.startsWith('/api')) {
        res.status(404).json({ error: 'Not found' });
        return;
      }
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // ── Global error handler (يجب أن يكون آخر middleware) ──
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('[Global Error]', err.message || err);
    res.status(err.status || 500).json({ error: 'Internal server error' });
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔐 Admin server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
