const OpenAI = require('openai');

let openai = null;

if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_openai_api_key_here') {
  openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
}

const ANALYSIS_SYSTEM_PROMPT = `You are an expert code security and quality analyzer. 
Analyze the provided code and return a structured JSON response with:
1. errors: syntax errors, bugs, logical issues
2. security_issues: OWASP-style security vulnerabilities (SQL injection, XSS, CSRF, insecure storage, etc.)
3. suggestions: code quality improvements, best practices
4. score: an integer 0–100 based on quality and security (100 = perfect)
5. summary: a 1-2 sentence overall assessment

Focus especially on: SQL injection, XSS, authentication issues, insecure data handling, 
unhandled errors, race conditions, memory leaks, and input validation.

Respond ONLY with valid JSON in this exact structure:
{
  "score": 75,
  "summary": "...",
  "errors": [
    { "line": 5, "severity": "error|warning|info", "type": "bug_type", "message": "...", "fix": "..." }
  ],
  "security_issues": [
    { "line": 12, "severity": "critical|high|medium|low", "type": "owasp_category", "message": "...", "fix": "..." }
  ],
  "suggestions": [
    { "type": "improvement_type", "message": "...", "example": "..." }
  ]
}`;

/**
 * Analyze code using OpenAI API
 */
const analyzeWithAI = async (code, language, challengeContext = '') => {
  if (!openai) {
    console.log('OpenAI not configured — using mock analyzer');
    return mockAnalyze(code, language);
  }

  const userPrompt = `Analyze this ${language} code${challengeContext ? ` (context: ${challengeContext})` : ''}:

\`\`\`${language}
${code}
\`\`\``;

  const response = await openai.chat.completions.create({
    model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
    messages: [
      { role: 'system', content: ANALYSIS_SYSTEM_PROMPT },
      { role: 'user', content: userPrompt },
    ],
    max_tokens: 1500,
    temperature: 0.2, // Low temp for consistent analysis
    response_format: { type: 'json_object' },
  });

  const content = response.choices[0].message.content;
  return JSON.parse(content);
};

/**
 * Mock analyzer used when OpenAI is not configured
 * Performs basic static analysis heuristics
 */
const mockAnalyze = (code, language) => {
  const errors = [];
  const security_issues = [];
  const suggestions = [];
  let score = 100;

  // Check for SQL injection patterns
  if (/['"`]\s*\+\s*(username|password|id|email|input|query)/i.test(code) ||
      /query\s*=\s*["'`].*\+/i.test(code)) {
    security_issues.push({
      line: findLineNumber(code, /\+\s*(username|password)/i) || 1,
      severity: 'critical',
      type: 'A03:2021-Injection',
      message: 'Potential SQL Injection: user input is concatenated directly into a query string.',
      fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE email = $1", [email])',
    });
    score -= 40;
  }

  // Check for innerHTML with variables
  if (/innerHTML\s*[+=]+\s*.*[^'"]\s*$/.test(code) ||
      /innerHTML\s*=\s*.*\+/.test(code)) {
    security_issues.push({
      line: findLineNumber(code, /innerHTML/) || 1,
      severity: 'high',
      type: 'A03:2021-XSS',
      message: 'Potential XSS: setting innerHTML with potentially unsanitized user data.',
      fix: 'Use textContent instead, or sanitize input with DOMPurify before inserting HTML.',
    });
    score -= 30;
  }

  // Check for plaintext passwords
  if (/password['":\s]*=\s*(password|pass|pw)/i.test(code) && !/bcrypt|hash|argon2/i.test(code)) {
    security_issues.push({
      line: findLineNumber(code, /password/) || 1,
      severity: 'critical',
      type: 'A02:2021-Cryptographic-Failures',
      message: 'Passwords appear to be stored or compared in plaintext.',
      fix: 'Use bcrypt: const hash = await bcrypt.hash(password, 12)',
    });
    score -= 35;
  }

  // Check for missing error handling
  const awaitCount = (code.match(/await /g) || []).length;
  const tryCatchCount = (code.match(/try\s*{/g) || []).length;
  if (awaitCount > 0 && tryCatchCount === 0) {
    errors.push({
      line: 1,
      severity: 'warning',
      type: 'missing_error_handling',
      message: `Found ${awaitCount} async operations without any try/catch blocks.`,
      fix: 'Wrap async operations in try/catch and handle errors explicitly.',
    });
    score -= 15;
  }

  // Check for eval usage
  if (/\beval\s*\(/.test(code)) {
    security_issues.push({
      line: findLineNumber(code, /\beval\s*\(/) || 1,
      severity: 'high',
      type: 'A03:2021-Injection',
      message: 'Use of eval() is a security risk and should be avoided.',
      fix: 'Replace eval() with safer alternatives like JSON.parse() or direct function calls.',
    });
    score -= 20;
  }

  // Memory leak detection
  if (/addEventListener/.test(code) && !/removeEventListener/.test(code) &&
      !/cleanup|destroy|unmount/i.test(code)) {
    errors.push({
      line: findLineNumber(code, /addEventListener/) || 1,
      severity: 'warning',
      type: 'memory_leak',
      message: 'Event listeners are added but never removed — potential memory leak.',
      fix: 'Store the listener reference and call removeEventListener in your cleanup function.',
    });
    score -= 10;
  }

  // Positive feedback
  if (/bcrypt|argon2|scrypt/.test(code)) {
    suggestions.push({ type: 'good_practice', message: 'Password hashing detected — good security practice!', example: null });
    score = Math.min(100, score + 5);
  }

  if (/parameterized|prepare|\$\d/.test(code)) {
    suggestions.push({ type: 'good_practice', message: 'Parameterized queries detected — SQL injection protection in place.', example: null });
    score = Math.min(100, score + 5);
  }

  // General suggestions
  if (!/\/\/|\/\*/.test(code)) {
    suggestions.push({ type: 'documentation', message: 'Consider adding comments to explain complex logic.', example: '// Describe what this section does' });
  }

  score = Math.max(0, score);

  const securityCount = security_issues.length;
  const errorCount = errors.length;
  const summary = securityCount + errorCount === 0
    ? 'Code looks good! No major issues detected.'
    : `Found ${securityCount} security issue(s) and ${errorCount} bug(s) that need attention.`;

  return {
    score,
    summary,
    errors,
    security_issues,
    suggestions,
    analyzed_by: 'mock_analyzer',
  };
};

/**
 * Find approximate line number for a regex match
 */
const findLineNumber = (code, regex) => {
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (regex.test(lines[i])) return i + 1;
  }
  return null;
};

module.exports = { analyzeWithAI };
