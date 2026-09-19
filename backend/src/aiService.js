function pickRandom(items) {
  return items[Math.floor(Math.random() * items.length)];
}

function normalizeFixSuggestion(type, fallbackFix) {
  const map = {
    'SQL Injection': 'Use parameterized queries or prepared statements; never concatenate raw request values into SQL strings.',
    'Command Injection': 'Reject untrusted command input, use allowlists, and avoid executing shell commands with user-controlled arguments.',
    'Path Traversal': 'Normalize the user-provided path, restrict access to a safe base directory, and reject traversal sequences such as ../.',
    'XSS': 'Encode user-controlled text before rendering and prefer safe templating or textContent over direct HTML injection.',
    'Hardcoded Secret': 'Move the secret into an environment variable or a secret manager and remove the credential from source code.'
  };

  return map[type] || fallbackFix;
}

function buildFallbackAiExplanation(finding) {
  const type = finding.type || 'security issue';
  const source = finding.source || 'user-controlled input';
  const sink = finding.sink || 'a dangerous sink';
  const fix = normalizeFixSuggestion(type, finding.fix || 'Validate and sanitize all untrusted input before it reaches sensitive APIs.');
  const flow = Array.isArray(finding.dataFlow) && finding.dataFlow.length > 0 ? finding.dataFlow.join(' → ') : `${source} → ${sink}`;

  const explanationTemplates = {
    'SQL Injection': [
      `The risky path begins at ${source}, and that value is later concatenated into a SQL statement before it reaches ${sink}. In practice, an attacker can inject extra query logic to alter the logic of the database call.`,
      `This code accepts data from ${source} and passes it into a query operation at ${sink}. Because the statement is assembled dynamically, a crafted payload can break out of the original query and execute unintended database actions.`,
      `The application is mixing untrusted input from ${source} into a database command executed by ${sink}. That makes the query structure attacker-controlled, which is a classic SQL injection pattern.`
    ],
    'Command Injection': [
      `The application takes user influence from ${source} and feeds it into ${sink}, creating a direct execution path for shell commands. An attacker can inject extra operators or commands to run unintended system instructions.`,
      `This issue is not just a string problem; the untrusted value from ${source} is eventually interpreted as executable system input at ${sink}. That means command syntax can be manipulated by the attacker.`,
      `The flow from ${source} to ${sink} demonstrates that external input reaches the operating system command layer. Once that happens, the injected payload can alter the command behavior or execute additional processes.`
    ],
    'Path Traversal': [
      `The path source originates from ${source}, then is combined with the file system access at ${sink}. Because the program does not normalize or restrict that value, an attacker may target files outside the intended directory.`,
      `This program accepts a file reference from ${source} and later reads or writes it via ${sink}. If the value contains traversal sequences, it can escape the application’s expected folder and access sensitive files.`,
      `The file path is derived from untrusted data flowing from ${source} into ${sink}. Without a safe base directory or validation, the application can be tricked into opening unintended files.`
    ],
    'XSS': [
      `The value from ${source} is forwarded into the browser-facing sink ${sink}, meaning attacker-controlled content can be rendered without proper escaping. That creates a strong chance of script execution in the victim’s browser.`,
      `The tainted value passes from ${source} to ${sink}, where it is embedded in markup or output. If an attacker supplies HTML or JavaScript payloads, the browser may interpret it as active content.`,
      `This data-flow path shows user-controlled content reaching a rendering sink at ${sink}. The application does not appear to neutralize dangerous HTML or script characters before outputting the value.`
    ],
    'Hardcoded Secret': [
      `The secret is embedded directly in source code rather than being isolated as runtime configuration. Because the value is visible in the codebase, it can be leaked accidentally through version control, logs, or debugging output.`,
      `The credential originates in the source tree and is not protected by a secret manager. Since it is hardcoded, anyone with repository access can recover it and abuse the related service.`,
      `This is a material exposure because the secret is stored in plain code instead of being supplied dynamically at runtime. That reduces operational security and makes compromise easier.`
    ]
  };

  const validationTemplates = {
    'SQL Injection': [
      `This is a credible finding because the flow shows a tainted value from ${source} reaching a database command at ${sink}. The exploitation path is realistic when the app accepts user values in request handlers or query parameters.`,
      `The reasoning is strong: the source is external and the sink is a query execution function. That pattern is a typical SQL injection path and should be treated as actionable.`,
      `The risk is not hypothetical; the app is mixing untrusted input with a query builder and then executing it. That gives attackers a direct injection surface.`,
      `This is a high-confidence candidate because it matches the classic source-to-sink pattern used in SQL injection detections.`
    ],
    'Command Injection': [
      `This is a strong candidate because command execution is reached from an externally supplied value. The data flow indicates user input is being composed into a shell command, which is exactly where command injection occurs.`,
      `The validation is convincing because the tainted value is passed directly into an execution API. That is one of the clearest indicators of command injection in application code.`,
      `The flow is sufficiently direct to consider this a real exploit vector rather than a benign false positive.`
    ],
    'Path Traversal': [
      `This finding is plausible because the file path is built from external input and later used in a file access call. That is a standard traversal pattern when no base directory restriction is enforced.`,
      `The validation is solid: the tainted value reaches file system access without normalization. It is likely exploitable when the path is attacker-controlled.`,
      `The code matches a classic path traversal pattern because the application trusts user-provided paths and reads files from them.`
    ],
    'XSS': [
      `This is a legitimate concern because an external value reaches a rendering sink without sanitization. That gives an attacker the ability to inject script-like content into the browser view.`,
      `The flow is credible: a tainted value is rendered in output, and the sink is HTML or response content. That is the core pattern behind cross-site scripting bugs.`,
      `This is likely a real issue because the application is outputting user-derived content directly into a context that the browser interprets as active markup.`
    ],
    'Hardcoded Secret': [
      `This is a credible secret exposure because the credential is embedded in the source tree and not derived from external secret storage. This is not just a style issue—it is a material security risk.`,
      `The validation is strong because the value is static in code and easily recoverable by anyone with code access. That is the exact scenario that secret management aims to prevent.`,
      `This is a practical exposure rather than a speculative one because the secret is stored in a visible source file.`
    ]
  };

  const explanation = pickRandom(explanationTemplates[type] || [
    `The value from ${source} reaches ${sink} without sufficient validation. This creates a meaningful risk because the data is untrusted and sensitive operations are being performed with it.`
  ]);

  const validation = pickRandom(validationTemplates[type] || [
    `This is a realistic security finding because the source and sink are connected by the application’s data flow.`
  ]);

  return {
    explanation: `${explanation} The observed flow is ${flow}.`,
    validation,
    fixSuggestion: fix,
    confidence: finding.confidence || 'medium'
  };
}

async function callOpenAi(finding) {
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    return null;
  }

  const dataFlow = Array.isArray(finding.dataFlow) && finding.dataFlow.length > 0 ? finding.dataFlow.join(' → ') : `${finding.source || 'user input'} → ${finding.sink || 'dangerous sink'}`;

  const prompt = `
    You are a senior security reviewer for source code.
    Analyze the finding below and return STRICT JSON with exactly these keys: explanation, validation, fixSuggestion, confidence.
    Keep the explanation to 3 sentences, avoid generic filler, mention the actual source and sink behavior, and explain why the issue matters.
    Do not include markdown or extra keys.

    {
      "type": "${finding.type || 'Security issue'}",
      "source": "${finding.source || 'user-controlled input'}",
      "sink": "${finding.sink || 'sensitive API'}",
      "dataFlow": "${dataFlow}",
      "impact": "${finding.impact || 'Unsafe data reaches a sensitive operation.'}",
      "fix": "${finding.fix || 'Validate and sanitize untrusted input.'}",
      "description": "${finding.description || 'Code pattern indicates a risky flow.'}",
      "snippet": "${(finding.snippet || '').replace(/"/g, '\\"')}"
    }
  `;

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        temperature: 0.7,
        messages: [
          {
            role: 'system',
            content: 'You are a secure coding assistant. Be concrete, technical, and concise. Return valid JSON only.'
          },
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || '';
    const parsed = JSON.parse(content);

    if (parsed && typeof parsed.explanation === 'string') {
      return {
        explanation: parsed.explanation,
        validation: parsed.validation || 'The model validated the finding based on the source-to-sink path and code context.',
        fixSuggestion: parsed.fixSuggestion || normalizeFixSuggestion(finding.type, finding.fix),
        confidence: parsed.confidence || finding.confidence || 'medium'
      };
    }
  } catch (error) {
    return null;
  }

  return null;
}

async function enrichFindingWithAi(finding) {
  const aiResponse = await callOpenAi(finding);
  if (aiResponse) {
    return {
      ...finding,
      ai: {
        explanation: aiResponse.explanation,
        validation: aiResponse.validation,
        fixSuggestion: aiResponse.fixSuggestion,
        confidence: aiResponse.confidence,
        source: 'openai'
      }
    };
  }

  const fallback = buildFallbackAiExplanation(finding);
  return {
    ...finding,
    ai: {
      explanation: fallback.explanation,
      validation: fallback.validation,
      fixSuggestion: fallback.fixSuggestion,
      confidence: fallback.confidence,
      source: 'fallback'
    }
  };
}

async function enrichFindingsWithAi(findings) {
  const enriched = [];

  for (const finding of findings) {
    enriched.push(await enrichFindingWithAi(finding));
  }

  return enriched;
}

module.exports = {
  enrichFindingWithAi,
  enrichFindingsWithAi
};
