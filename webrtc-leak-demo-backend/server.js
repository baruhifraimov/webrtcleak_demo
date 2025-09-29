const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const port = 9999;

// --- Configuration ---
// Enable CORS to allow your frontend to send requests to this server.
app.use(cors());
// Enable parsing of JSON bodies, with a higher limit for large fingerprint data.
app.use(express.json({ limit: '50mb' }));

// Define the absolute path for the log file.
const logFilePath = path.join(__dirname, 'leak.log');

// --- API Endpoint for Logging ---
// This creates the '/log' endpoint that the frontend will send data to.
app.post('/log', (req, res) => {
  // Extract the log content sent from the frontend.
  const { logContent } = req.body;

  if (!logContent) {
    console.error('Received request with no log content.');
    return res.status(400).send('No log content received.');
  }

  // Format the entry with a timestamp.
  const logEntry = `--- New Client Entry: ${new Date().toISOString()} ---\n${logContent}\n\n`;

  // --- The Core Logging Logic ---
  // Asynchronously append the new entry to 'leak.log'.
  // This creates the file if it doesn't exist.
  fs.appendFile(logFilePath, logEntry, (err) => {
    if (err) {
      console.error('Failed to write to log file:', err);
      return res.status(500).send('Failed to write to log file.');
    }
    console.log('Successfully logged new client entry.');
    res.status(200).send('Log received.');
  });
});

// --- Start the Server ---
app.listen(port, () => {
  console.log(`Leak log server listening at http://localhost:${port}`);
  console.log(`Logs will be saved to: ${logFilePath}`);
});
