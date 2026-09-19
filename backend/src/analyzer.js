const fs = require('fs');
const path = require('path');

const SUPPORTED_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'
]);

const severityOrder = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

function listFilesRecursively(dir) {
  let files = [];

  if (!fs.existsSync(dir)) {
    return files;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files = files.concat(listFilesRecursively(entryPath));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }

  return files;
}

function getLineNumber(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}

function extractSnippet(content, lineNumber) {
  const lines = content.split(/\r?\n/);
  return lines[Math.max(0, lineNumber - 1)] || '';
}

function buildFinding({
  type,
  severity,
  confidence,
  file,
  line,
  snippet,
  source,
  sink,
  impact,
  fix,
  description
}) {
  return {
    id: `${type.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    type,
    severity,
    confidence,
    file,
    line,
    snippet,
    source,
    sink,
    impact,
    fix,
    description
  };
}

function detectSqlInjection(filePath, content) {
  const findings = [];
  const patterns = [
    {
      pattern: /(SELECT|INSERT|UPDATE|DELETE|CREATE).*?(?:\+|\$\{).+/gi,
      source: 'User-controlled request data or application variables',
      sink: 'Database query execution',
      impact: 'Attackers can manipulate SQL queries to read, modify or delete database records.',
      fix: 'Use parameterized queries or ORM prepared statements instead of concatenating user data.',
      description: 'A SQL statement is being assembled from dynamic input.'
    },
    {
      pattern: /(?:db|connection)\.(?:query|execute|raw)\s*\(\s*["'`].*?(?:\+|\$\{)/gi,
      source: 'Client request fields or app variables',
      sink: 'query() / execute() call',
      impact: 'Untrusted input reaches the database layer without validation, making injection possible.',
      fix: 'Bind user input as parameters and avoid string interpolation in SQL statements.',
      description: 'Dynamic values reach the database query call directly.'
    }
  ];

  for (const rule of patterns) {
    const regex = new RegExp(rule.pattern);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const line = getLineNumber(content, match.index);
      findings.push(buildFinding({
        type: 'SQL Injection',
        severity: 'high',
        confidence: 'high',
        file: filePath,
        line,
        snippet: extractSnippet(content, line),
        source: rule.source,
        sink: rule.sink,
        impact: rule.impact,
        fix: rule.fix,
        description: rule.description
      }));
    }
  }

  return findings;
}

function detectXss(filePath, content) {
  const findings = [];
  const patterns = [
    {
      pattern: /(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=?\s*.*?(?:req\.(body|query|params)|document\.getElementById|window\.location|\w+)/gi,
      source: 'Request data or DOM value',
      sink: 'HTML injection into the browser',
      impact: 'The application can render attacker-controlled HTML or script content.',
      fix: 'Use textContent or a safe template engine and sanitize untrusted content before rendering.',
      description: 'Data from the request or DOM is inserted into HTML content without escaping.'
    },
    {
      pattern: /res\.(?:send|write)\s*\(\s*.*?(?:\+|\$\{|\w+)/gi,
      source: 'User input or derived response value',
      sink: 'HTTP response rendering',
      impact: 'The response may contain untrusted script or HTML that is executed by the browser.',
      fix: 'Sanitize output and escape HTML before returning it in responses.',
      description: 'Dynamic values are returned directly in the HTTP response.'
    }
  ];

  for (const rule of patterns) {
    const regex = new RegExp(rule.pattern);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const line = getLineNumber(content, match.index);
      findings.push(buildFinding({
        type: 'Cross-Site Scripting (XSS)',
        severity: 'high',
        confidence: 'medium',
        file: filePath,
        line,
        snippet: extractSnippet(content, line),
        source: rule.source,
        sink: rule.sink,
        impact: rule.impact,
        fix: rule.fix,
        description: rule.description
      }));
    }
  }

  return findings;
}

function detectCommandInjection(filePath, content) {
  const findings = [];
  const patterns = [
    {
      pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*["'`].*?(?:\+|\$\{)/gi,
      source: 'User input or CLI arguments',
      sink: 'Operating system command execution',
      impact: 'An attacker can run arbitrary system commands on the server.',
      fix: 'Validate input and use safe APIs that avoid shell command execution with untrusted data.',
      description: 'A shell command is assembled from dynamic input.'
    }
  ];

  for (const rule of patterns) {
    const regex = new RegExp(rule.pattern);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const line = getLineNumber(content, match.index);
      findings.push(buildFinding({
        type: 'Command Injection',
        severity: 'critical',
        confidence: 'high',
        file: filePath,
        line,
        snippet: extractSnippet(content, line),
        source: rule.source,
        sink: rule.sink,
        impact: rule.impact,
        fix: rule.fix,
        description: rule.description
      }));
    }
  }

  return findings;
}

function detectPathTraversal(filePath, content) {
  const findings = [];
  const patterns = [
    {
      pattern: /(?:readFileSync|readFile|writeFile|createReadStream|fs\.)\s*\(\s*["'`].*?(?:\+|\$\{)/gi,
      source: 'User-controlled path or filename',
      sink: 'File system access',
      impact: 'Attackers could read or overwrite files outside the intended folder.',
      fix: 'Validate and normalize the path and restrict access to an allowlisted directory.',
      description: 'A file operation uses a path derived from dynamic input.'
    }
  ];

  for (const rule of patterns) {
    const regex = new RegExp(rule.pattern);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const line = getLineNumber(content, match.index);
      findings.push(buildFinding({
        type: 'Path Traversal',
        severity: 'high',
        confidence: 'medium',
        file: filePath,
        line,
        snippet: extractSnippet(content, line),
        source: rule.source,
        sink: rule.sink,
        impact: rule.impact,
        fix: rule.fix,
        description: rule.description
      }));
    }
  }

  return findings;
}

function detectHardcodedSecrets(filePath, content) {
  const findings = [];
  const patterns = [
    {
      pattern: /(?:const|let|var)\s+(?:apiKey|secret|token|password|privateKey)\s*=\s*["'`][^"'`]{8,}["'`]/gi,
      source: 'Application configuration',
      sink: 'Credential storage in code',
      impact: 'Sensitive credentials are exposed in the source tree and can be leaked through repositories or logs.',
      fix: 'Move secrets to environment variables or a secure vault and never commit them to source control.',
      description: 'A secret or credential appears directly in the source code.'
    }
  ];

  for (const rule of patterns) {
    const regex = new RegExp(rule.pattern);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const line = getLineNumber(content, match.index);
      findings.push(buildFinding({
        type: 'Hardcoded Secret',
        severity: 'medium',
        confidence: 'high',
        file: filePath,
        line,
        snippet: extractSnippet(content, line),
        source: rule.source,
        sink: rule.sink,
        impact: rule.impact,
        fix: rule.fix,
        description: rule.description
      }));
    }
  }

  return findings;
}

function analyzeProject(projectRoot) {
  const files = listFilesRecursively(projectRoot);
  const findings = [];

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(ext)) {
      continue;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const relativePath = path.relative(projectRoot, filePath).replace(/\\/g, '/');

    findings.push(...detectSqlInjection(relativePath, content));
    findings.push(...detectXss(relativePath, content));
    findings.push(...detectCommandInjection(relativePath, content));
    findings.push(...detectPathTraversal(relativePath, content));
    findings.push(...detectHardcodedSecrets(relativePath, content));
  }

  const deduplicated = findings.filter((item, index, arr) => {
    const key = `${item.file}:${item.line}:${item.type}:${item.snippet}`;
    return arr.findIndex(other => `${other.file}:${other.line}:${other.type}:${other.snippet}` === key) === index;
  });

  deduplicated.sort((a, b) => {
    return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
  });

  const summary = {
    total: deduplicated.length,
    critical: deduplicated.filter(item => item.severity === 'critical').length,
    high: deduplicated.filter(item => item.severity === 'high').length,
    medium: deduplicated.filter(item => item.severity === 'medium').length,
    low: deduplicated.filter(item => item.severity === 'low').length,
    info: deduplicated.filter(item => item.severity === 'info').length
  };

  return {
    status: 'success',
    projectRoot,
    summary,
    findings: deduplicated
  };
}

module.exports = {
  analyzeProject
};
