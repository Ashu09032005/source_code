const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const { analyzeProject } = require('./src/analyzer');

const app = express();
const PORT = process.env.PORT || 3000;
const backendDir = __dirname;
const frontendDir = path.join(backendDir, '..', 'frontend');
const uploadDir = path.join(backendDir, 'uploads');
const sampleProjectDir = path.join(backendDir, 'sample-project');

fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const safeName = file.originalname.replace(/\s+/g, '-').toLowerCase();
    cb(null, `${Date.now()}-${safeName}`);
  }
});

const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
      cb(null, true);
    } else {
      cb(new Error('Only ZIP files are allowed.'));
    }
  }
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(frontendDir));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Vulnerability analyzer is running.' });
});

app.get('/api/demo', (req, res) => {
  try {
    const result = analyzeProject(sampleProjectDir);
    res.json({
      projectName: 'Demo vulnerable application',
      source: 'sample-project',
      ...result
    });
  } catch (error) {
    console.error('Demo analysis failed:', error);
    res.status(500).json({ error: 'Unable to analyze the demo project.' });
  }
});

app.post('/api/upload', upload.single('project'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No ZIP file uploaded.' });
    }

    const zipPath = path.join(uploadDir, req.file.filename);
    const extractDir = path.join(uploadDir, `project-${Date.now()}`);
    fs.mkdirSync(extractDir, { recursive: true });

    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractDir, true);

    const result = analyzeProject(extractDir);

    res.json({
      projectName: req.file.originalname.replace(/\.zip$/i, ''),
      source: 'uploaded-zip',
      ...result
    });
  } catch (error) {
    console.error('Upload analysis failed:', error);
    res.status(500).json({ error: 'Failed to analyze the uploaded project.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    return res.status(400).json({ error: error.message });
  }

  if (error) {
    return res.status(400).json({ error: error.message || 'Unexpected upload error.' });
  }

  next();
});

app.listen(PORT, () => {
  console.log(`Explainable Vulnerability Analyzer running on http://localhost:${PORT}`);
});
