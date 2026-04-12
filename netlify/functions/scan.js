'use strict';

/**
 * Netlify Serverless Function — /api/scan
 * Runs in AWS Lambda (Node.js) — full Node.js built-ins available.
 */

const { runScan } = require('../../lib/scanner');

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed.' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON.' }) };
  }

  const { url, consent } = body;

  if (!consent)
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'You must confirm authorization to scan this website.' }) };

  if (!url || typeof url !== 'string' || url.length > 500)
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'A valid URL is required.' }) };

  const result = await runScan(url.trim());

  if (result.error)
    return { statusCode: 400, headers, body: JSON.stringify(result) };

  return { statusCode: 200, headers, body: JSON.stringify(result) };
};
