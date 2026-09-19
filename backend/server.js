const express = require('express');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const { analyzeProject } = require('./src/analyzer');
const { enrichFindingsWithAi } = require('./src/aiService');

const app = express();
app.locals.lastReport = null;
const PORT = process.env.PORT || 5000;
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
  res.json({ status: 'ok', message: 'Explainable source-code security pipeline is running.' });
});

function buildReport(projectName, source, result, findings) {
  return {
    projectName,
    source,
    generatedAt: new Date().toISOString(),
    summary: result.summary,
    findings,
    pipeline: result.pipeline,
    aiSummary: {
      overview: 'The static analysis pipeline detects suspicious flows, and the AI layer explains the likely root cause and safe fix.',
      enabled: !!process.env.OPENAI_API_KEY,
      model: process.env.OPENAI_API_KEY ? 'OpenAI GPT-4o mini' : 'Fallback reasoning engine'
    }
  };
}

app.get('/api/demo', async (req, res) => {
  try {
    const result = analyzeProject(sampleProjectDir);
    const findings = await enrichFindingsWithAi(result.findings || []);
    const report = buildReport('Demo vulnerable application', 'sample-project', result, findings);
    app.locals.lastReport = report;
    res.json(report);
  } catch (error) {
    console.error('Demo analysis failed:', error);
    res.status(500).json({ error: 'Unable to analyze the demo project.' });
  }
});

app.post('/api/upload', upload.single('project'), async (req, res) => {
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
    const findings = await enrichFindingsWithAi(result.findings || []);
    const report = buildReport(req.file.originalname.replace(/\.zip$/i, ''), 'uploaded-zip', result, findings);
    app.locals.lastReport = report;

    res.json(report);
  } catch (error) {
    console.error('Upload analysis failed:', error);
    res.status(500).json({ error: 'Failed to analyze the uploaded project.' });
  }
});

app.get('/api/report', (req, res) => {
  if (!app.locals.lastReport) {
    return res.status(404).json({ error: 'No report has been generated yet.' });
  }

  res.json(app.locals.lastReport);
});

app.get('/api/report/download', (req, res) => {
  if (!app.locals.lastReport) {
    return res.status(404).json({ error: 'No report has been generated yet.' });
  }

  const fileName = `${(app.locals.lastReport.projectName || 'security-report').replace(/\s+/g, '-').toLowerCase()}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(app.locals.lastReport, null, 2));
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
  console.log(`Explainable Source-Code Security Pipeline running on http://localhost:${PORT}`);
});
