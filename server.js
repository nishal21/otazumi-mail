import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());

// CORS configuration - Update with your frontend domain
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
  'http://localhost:5173',
  'http://localhost:4173',
  'https://otazumi.netlify.app',
  'https://otazumi.page',
  'https://www.otazumi.page'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
};

app.use(cors(corsOptions));

// Add explicit CORS headers for Vercel (must be before routes)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Always set CORS headers - allow the requesting origin if it's in our list
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else if (!origin) {
    // For requests without origin (like curl), allow all
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else {
    // For unknown origins, allow the main domain
    res.setHeader('Access-Control-Allow-Origin', 'https://otazumi.netlify.app');
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Authorization, Accept, Origin');
  res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
  
  // Handle preflight OPTIONS request immediately
  if (req.method === 'OPTIONS') {
    console.log('✅ Handling OPTIONS preflight for:', req.url, 'from origin:', origin);
    return res.status(204).end();
  }
  
  next();
});

// Body parser
app.use(express.json({ limit: '10mb' }));

// Rate limiting - 10 emails per 15 minutes per IP
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many emails sent from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Create nodemailer transporter
let transporter;

// Configure transporter based on provider
const setupTransporter = () => {
  const provider = process.env.EMAIL_PROVIDER || 'gmail';

  console.log('🔧 Setting up email transporter with provider:', provider);

  if (provider === 'gmail') {
    // Gmail configuration
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_APP_PASSWORD, // Use App Password, not regular password
      },
    });
  } else if (provider === 'custom') {
    // Custom SMTP configuration (e.g., Hostinger, Namecheap, etc.)
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    });
  } else if (provider === 'sendgrid') {
    // SendGrid SMTP
    transporter = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY,
      },
    });
  } else {
    console.error('❌ Invalid EMAIL_PROVIDER. Use: gmail, custom, or sendgrid');
    process.exit(1);
  }

  // Verify transporter configuration
  transporter.verify((error, success) => {
    if (error) {
      console.error('❌ SMTP Configuration Error:', error);
      console.error('Please check your EMAIL_PROVIDER and SMTP credentials in .env');
    } else {
      console.log('✅ SMTP Server is ready to send emails');
    }
  });
};

setupTransporter();

// Root endpoint - API documentation
app.get('/', (req, res) => {
  res.json({
    service: 'Otazumi Email & OAuth Server',
    version: '1.1.0',
    status: 'running',
    endpoints: {
      'GET /': 'API documentation (this page)',
      'GET /health': 'Health check endpoint',
      'POST /api/send-email': 'Send email endpoint',
      'POST /api/oauth/anilist/token': 'Exchange AniList OAuth code for token',
      'POST /api/oauth/mal/token': 'Exchange MyAnimeList OAuth code for token'
    },
    email: {
      method: 'POST',
      url: '/api/send-email',
      body: {
        to: 'recipient@example.com',
        subject: 'Email subject',
        html: '<h1>HTML content</h1>',
        text: 'Plain text content (optional)'
      }
    },
    oauth: {
      anilist: {
        method: 'POST',
        url: '/api/oauth/anilist/token',
        body: {
          code: 'authorization_code_from_anilist',
          redirectUri: 'https://yourdomain.com/auth/anilist/callback'
        }
      },
      myanimelist: {
        method: 'POST',
        url: '/api/oauth/mal/token',
        body: {
          code: 'authorization_code_from_mal',
          codeVerifier: 'pkce_code_verifier',
          redirectUri: 'https://yourdomain.com/auth/mal/callback'
        }
      }
    },
    provider: process.env.EMAIL_PROVIDER || 'gmail',
    timestamp: new Date().toISOString(),
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Otazumi Email Server',
    timestamp: new Date().toISOString(),
  });
});

// Send email endpoint
app.post('/api/send-email', emailLimiter, async (req, res) => {
  try {
    const { to, subject, html, text, from } = req.body;

    // Validation
    if (!to || !subject || (!html && !text)) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: to, subject, and (html or text)',
      });
    }

    // Email options
    const mailOptions = {
      from: from || `${process.env.FROM_NAME || 'Otazumi'} <${process.env.FROM_EMAIL}>`,
      to,
      subject,
      html: html || text,
      text: text || html.replace(/<[^>]*>/g, ''), // Strip HTML for text version
    };

    console.log('📧 Sending email to:', to);
    console.log('📋 Subject:', subject);

    // Send email
    const info = await transporter.sendMail(mailOptions);

    console.log('✅ Email sent successfully:', info.messageId);

    res.json({
      success: true,
      messageId: info.messageId,
      message: 'Email sent successfully',
    });
  } catch (error) {
    console.error('❌ Error sending email:', error);

    // Distinguish between different error types
    if (error.code === 'EAUTH') {
      return res.status(401).json({
        success: false,
        error: 'Authentication failed. Check SMTP credentials.',
      });
    } else if (error.code === 'ECONNECTION') {
      return res.status(503).json({
        success: false,
        error: 'Connection to SMTP server failed.',
      });
    }

    res.status(500).json({
      success: false,
      error: 'Failed to send email',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
});

// OAuth endpoints for external platform authentication
app.post('/api/oauth/anilist/token', async (req, res) => {
  try {
    const { code, redirectUri } = req.body;

    if (!code || !redirectUri) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: code and redirectUri',
      });
    }

    console.log('🔄 Exchanging AniList authorization code for token...');

    const tokenResponse = await fetch('https://anilist.co/api/v2/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: process.env.ANILIST_CLIENT_ID,
        client_secret: process.env.ANILIST_CLIENT_SECRET,
        redirect_uri: redirectUri,
        code: code,
      }),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text();
      console.error('❌ AniList token exchange failed:', errorData);
      return res.status(tokenResponse.status).json({
        success: false,
        error: 'Failed to exchange authorization code',
      });
    }

    const tokenData = await tokenResponse.json();
    console.log('✅ AniList token exchange successful');

    res.json({
      success: true,
      ...tokenData,
    });
  } catch (error) {
    console.error('❌ AniList OAuth error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during OAuth token exchange',
    });
  }
});

app.post('/api/oauth/mal/token', async (req, res) => {
  try {
    const { code, codeVerifier, redirectUri } = req.body;

    if (!code || !codeVerifier || !redirectUri) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: code, codeVerifier, and redirectUri',
      });
    }

    console.log('🔄 Exchanging MyAnimeList authorization code for token...');

    const tokenResponse = await fetch('https://myanimelist.net/v1/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: process.env.MAL_CLIENT_ID,
        client_secret: process.env.MAL_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text();
      console.error('❌ MyAnimeList token exchange failed:', errorData);
      return res.status(tokenResponse.status).json({
        success: false,
        error: 'Failed to exchange authorization code',
      });
    }

    const tokenData = await tokenResponse.json();
    console.log('✅ MyAnimeList token exchange successful');

    res.json({
      success: true,
      ...tokenData,
    });
  } catch (error) {
    console.error('❌ MyAnimeList OAuth error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during OAuth token exchange',
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

// Start server
app.listen(PORT, () => {
  console.log('🚀 Otazumi Email Server running on port', PORT);
  console.log('📧 Provider:', process.env.EMAIL_PROVIDER || 'gmail');
  console.log('📬 From:', process.env.SMTP_USER);
  console.log('🌐 Allowed origins:', allowedOrigins.join(', '));
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT signal received: closing HTTP server');
  process.exit(0);
});
