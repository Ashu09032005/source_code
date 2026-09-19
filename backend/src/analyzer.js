const fs = require('fs');
const path = require('path');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

const SUPPORTED_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);

const severityOrder = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const SOURCE_IDENTIFIERS = new Set(['req.body', 'req.query', 'req.params', 'req.headers', 'process.env', 'process.argv']);
const SINK_TYPES = {
  SQLInjection: { severity: 'high', confidence: 'high' },
  XSS: { severity: 'high', confidence: 'medium' },
  CommandInjection: { severity: 'critical', confidence: 'high' },
  PathTraversal: { severity: 'high', confidence: 'medium' },
  HardcodedSecret: { severity: 'medium', confidence: 'high' }
};

function listFilesRecursively(dir) {
  let files = [];
  if (!fs.existsSync(dir)) return files;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) files = files.concat(listFilesRecursively(entryPath));
    else if (entry.isFile()) files.push(entryPath);
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

function buildFinding({ type, severity, confidence, file, line, snippet, source, sink, impact, fix, description, dataFlow }) {
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
    description,
    dataFlow
  };
}

function toExpressionText(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral' || node.type === 'Literal') return String(node.value);
  if (node.type === 'MemberExpression') {
    const objectText = toExpressionText(node.object);
    const propertyText = toExpressionText(node.property);
    return objectText && propertyText ? `${objectText}.${propertyText}` : objectText || propertyText || '';
  }
  if (node.type === 'BinaryExpression') {
    return `${toExpressionText(node.left)} ${node.operator} ${toExpressionText(node.right)}`;
  }
  if (node.type === 'CallExpression') {
    return `${toExpressionText(node.callee)}()`;
  }
  return '';
}

function expressionContainsTainted(expr, taintedVars) {
  if (!expr) return false;
  if (expr.type === 'Identifier') return taintedVars.has(expr.name);
  if (expr.type === 'MemberExpression') {
    const text = toExpressionText(expr);
    return [...taintedVars.keys()].some(key => text.includes(key));
  }
  if (expr.type === 'BinaryExpression') {
    return expressionContainsTainted(expr.left, taintedVars) || expressionContainsTainted(expr.right, taintedVars);
  }
  if (expr.type === 'LogicalExpression') {
    return expressionContainsTainted(expr.left, taintedVars) || expressionContainsTainted(expr.right, taintedVars);
  }
  if (expr.type === 'CallExpression') {
    return expr.arguments.some(arg => expressionContainsTainted(arg, taintedVars));
  }
  return false;
}

function isDirectSource(node) {
  if (!node) return false;
  const exprText = toExpressionText(node);
  return SOURCE_IDENTIFIERS.has(exprText) || /req\.(body|query|params|headers)/.test(exprText) || /process\.(env|argv)/.test(exprText);
}

function getCallName(node) {
  if (!node || !node.callee) return '';
  if (node.callee.type === 'Identifier') return node.callee.name;
  if (node.callee.type === 'MemberExpression') return toExpressionText(node.callee);
  return '';
}

function getLineInfo(content, loc) {
  if (!loc) return { line: 1, snippet: '' };
  const line = loc.start.line;
  const snippet = extractSnippet(content, line);
  return { line, snippet };
}

function createAiExplanation(type, source, sink, flow) {
  return `The application receives untrusted value from ${source}, passes it through ${flow.join(' → ') || 'the data flow'}, and eventually reaches ${sink}. This creates a ${type.toLowerCase()} issue because user-controlled information is reaching a sensitive operation without validation or sanitization.`;
}

function analyzeFile(filePath, content) {
  const findings = [];
  const sources = [];
  const sinks = [];
  const dataFlow = [];

  let ast;
  try {
    ast = parser.parse(content, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript', 'classProperties']
    });
  } catch (error) {
    return { findings, sources, sinks, dataFlow };
  }

  const taintedVars = new Map();

  traverse(ast, {
    VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;
      if (!id || id.type !== 'Identifier') return;

      if (isDirectSource(init)) {
        taintedVars.set(id.name, toExpressionText(init));
        sources.push({ variable: id.name, source: toExpressionText(init), file: filePath });
      } else if (init && expressionContainsTainted(init, taintedVars)) {
        taintedVars.set(id.name, toExpressionText(init));
        dataFlow.push({ variable: id.name, from: toExpressionText(init), file: filePath });
      }
    },

    AssignmentExpression(path) {
      const left = path.node.left;
      const right = path.node.right;
      if (!left || left.type !== 'Identifier') return;
      if (isDirectSource(right) || expressionContainsTainted(right, taintedVars)) {
        taintedVars.set(left.name, toExpressionText(right));
        dataFlow.push({ variable: left.name, from: toExpressionText(right), file: filePath });
      }
    },

    CallExpression(path) {
      const callName = getCallName(path.node);
      const args = path.node.arguments || [];

      if (!callName) return;

      const sinkMatch = {
        'db.query': { type: 'SQL Injection', rule: 'query injection' },
        'db.execute': { type: 'SQL Injection', rule: 'query injection' },
        'exec': { type: 'Command Injection', rule: 'command execution' },
        'execSync': { type: 'Command Injection', rule: 'command execution' },
        'spawn': { type: 'Command Injection', rule: 'command execution' },
        'readFileSync': { type: 'Path Traversal', rule: 'file access' },
        'readFile': { type: 'Path Traversal', rule: 'file access' },
        'writeFile': { type: 'Path Traversal', rule: 'file access' },
        'innerHTML': { type: 'XSS', rule: 'html rendering' },
        'res.send': { type: 'XSS', rule: 'response rendering' },
        'res.write': { type: 'XSS', rule: 'response rendering' }
      };

      const matched = sinkMatch[callName] || Object.entries(sinkMatch).find(([patternKey]) => callName.includes(patternKey));
      const sinkRule = matched ? matched[1] || matched : null;
      if (!sinkRule) return;

      const taintedArg = args.find(arg => expressionContainsTainted(arg, taintedVars) || isDirectSource(arg));
      if (!taintedArg) return;

      const sourceValue = toExpressionText(taintedArg);
      const flow = [sourceValue];
      const variableName = sourceValue.split(/[.\[]/).pop() || sourceValue;
      if (variableName && variableName !== sourceValue) flow.push(variableName);
      flow.push(callName);

      const { line, snippet } = getLineInfo(content, path.node.loc);
      const sinkType = sinkRule.type;
      const meta = SINK_TYPES[sinkType] || { severity: 'medium', confidence: 'medium' };

      sinks.push({ file: filePath, sink: callName, type: sinkType, line });
      findings.push(buildFinding({
        type: sinkType,
        severity: meta.severity,
        confidence: meta.confidence,
        file: filePath,
        line,
        snippet,
        source: sourceValue.includes('.') ? sourceValue : `User-controlled value: ${sourceValue}`,
        sink: callName,
        impact: `The value from ${sourceValue} reaches ${callName}, which creates a ${sinkType.toLowerCase()} risk in the application.`,
        fix: getFixRecommendation(sinkType),
        description: `This is a candidate ${sinkType} instance found via source-to-sink analysis.`,
        dataFlow: flow
      }));
    }
  });

  return { findings, sources, sinks, dataFlow };
}

function getFixRecommendation(type) {
  const recommendations = {
    'SQL Injection': 'Use parameterized queries and avoid string concatenation when composing SQL statements.',
    'Command Injection': 'Validate user input and avoid executing shell commands with untrusted data; use safer APIs or allowlists.',
    'Path Traversal': 'Normalize and restrict file access to a safe directory and validate user-provided paths before reading or writing files.',
    'XSS': 'Encode or sanitize output before rendering it in HTML, and prefer safe template rendering or textContent.',
    'Hardcoded Secret': 'Move credentials to environment variables or a secret manager and never commit them to source code.'
  };

  return recommendations[type] || 'Validate inputs and isolate unsafe operations behind secure, allowlisted controls.';
}

function analyzeProject(projectRoot) {
  const files = listFilesRecursively(projectRoot);
  const findings = [];
  const sources = [];
  const sinks = [];
  const dataFlow = [];

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(ext)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    const relativePath = path.relative(projectRoot, filePath).replace(/\\/g, '/');

    const analysis = analyzeFile(relativePath, content);
    findings.push(...analysis.findings);
    sources.push(...analysis.sources);
    sinks.push(...analysis.sinks);
    dataFlow.push(...analysis.dataFlow);
  }

  const deduplicated = findings.filter((item, index, arr) => {
    const key = `${item.file}:${item.line}:${item.type}:${item.snippet}`;
    return arr.findIndex(other => `${other.file}:${other.line}:${other.type}:${other.snippet}` === key) === index;
  });

  deduplicated.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));

  const summary = {
    total: deduplicated.length,
    critical: deduplicated.filter(item => item.severity === 'critical').length,
    high: deduplicated.filter(item => item.severity === 'high').length,
    medium: deduplicated.filter(item => item.severity === 'medium').length,
    low: deduplicated.filter(item => item.severity === 'low').length,
    info: deduplicated.filter(item => item.severity === 'info').length
  };

  const pipeline = {
    sources: [...new Map(sources.map(item => [`${item.file}:${item.variable}`, item])).values()],
    sinks: [...new Map(sinks.map(item => [`${item.file}:${item.sink}:${item.type}`, item])).values()],
    dataFlow: [...new Map(dataFlow.map(item => [`${item.file}:${item.variable}:${item.from}`, item])).values()]
  };

  return {
    status: 'success',
    projectRoot,
    summary,
    findings: deduplicated,
    pipeline,
    aiSummary: {
      overview: 'The system parses the project, tracks tainted sources, detects dangerous sinks, validates the path, and generates an explainable security report.',
      explanation: 'The AI layer explains how untrusted input flows into potentially unsafe operations and recommends secure remediation steps.'
    }
  };
}

module.exports = {
  analyzeProject
};
