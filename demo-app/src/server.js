const express = require('express');
const config = require('./config');
const { corsMiddleware } = require('./middleware/cors');
const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();

app.use(corsMiddleware);
app.use(express.json());

// Routes
app.use('/auth', authRoutes);
app.use('/api', protectedRoutes);

// Error handler
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`Demo authentication server listening on port ${config.port}`);
  });
}

module.exports = app;
