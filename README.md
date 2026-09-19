# Explainable Vulnerability Analyzer

This project is a unique full-stack application for source code security analysis. It uses Node.js + Express for the backend and a simple frontend for uploading ZIP projects or loading a demo project.

## Features

- Upload a ZIP archive containing a source code project
- Demostrates explainable vulnerability analysis for JavaScript/TypeScript files
- Detects common issues such as SQL injection, XSS, command injection, path traversal, and hardcoded secrets
- Explains the vulnerability with source, sink, impact, and secure fix advice
- Shows a clear summary of findings by severity

## Run the app

1. Open a terminal in the `backend` folder.
2. Install dependencies:
   npm install
3. Start the server:
   npm start
4. Open the browser at:
   http://localhost:3000

## Demo project

The backend includes a small sample project with intentionally vulnerable code. You can load it from the UI using the `Load Demo Project` button.

## Project structure

- `backend/server.js` - Express server and API endpoints
- `backend/src/analyzer.js` - vulnerability detection engine
- `backend/sample-project` - demo vulnerable project
- `frontend/index.html` - UI layout
- `frontend/styles.css` - styling
- `frontend/app.js` - frontend logic

## Notes

This is a prototype that focuses on explainability and a clean developer workflow, rather than being a full production-grade static analyzer.
