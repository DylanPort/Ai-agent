// backend/backend.js
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import { createLogger, format, transports } from 'winston';
import { v4 as uuidv4 } from 'uuid';
import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Connection, PublicKey } from '@solana/web3.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.simple()
  ),
  transports: [
    new transports.Console()
  ]
});

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
if (!OPENAI_API_KEY) {
  logger.error("OPENAI_API_KEY not set. Please set it before running.");
  process.exit(1);
}

// Constants
const REQUIRED_TOKENS = 200000;
const CYRUS_MINT_ADDRESS = new PublicKey("4oJh9x5Cr14bfaBtUsXN1YUZbxRhuae9nrkSyWGSpump");
const RPC_ENDPOINT = "https://api.mainnet-beta.solana.com";

// Setup Solana connection
const connection = new Connection(RPC_ENDPOINT, "confirmed");

// In-memory storage
// usersData[publicKey] = { agents: [ {id, email, username, password, character, running, logs:[] } ] }
const usersData = {};
const agentProcesses = {};

// Real token check function
async function checkUserTokenBalance(publicKeyStr) {
  try {
    const ownerPubKey = new PublicKey(publicKeyStr);
    const parsedTokenAccounts = await connection.getParsedTokenAccountsByOwner(ownerPubKey, {
      programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    });

    const tokenAccount = parsedTokenAccounts.value.find(
      acc => acc.account.data.parsed.info.mint === CYRUS_MINT_ADDRESS.toBase58()
    );

    if (!tokenAccount) {
      // No account for CYRUS token
      return false;
    }

    const uiAmount = tokenAccount.account.data.parsed.info.tokenAmount.uiAmount;
    return uiAmount >= REQUIRED_TOKENS;
  } catch (error) {
    logger.error("Error checking token balance:", error);
    return false;
  }
}

// Path to agent-runner.js
const agentRunnerPath = path.join(__dirname, 'agent-runner.js');
if (!fs.existsSync(agentRunnerPath)) {
  logger.error("agent-runner.js not found. Please ensure it exists in the backend directory.");
  process.exit(1);
}

// Function to start an agent process
function startAgentProcess(agent) {
  const child = spawn('node', [agentRunnerPath], {
    env: {
      ...process.env,
      TWITTER_EMAIL: agent.email,
      TWITTER_USERNAME: agent.username,
      TWITTER_PASSWORD: agent.password,
      AGENT_CHARACTER: agent.character,
      OPENAI_API_KEY: OPENAI_API_KEY
    }
  });

  const logs = agent.logs;
  child.stdout.on('data', (data) => {
    const line = data.toString().trim();
    logs.push(`[${new Date().toISOString()}] ${line}`);
    if (logs.length > 500) logs.shift();
  });

  child.stderr.on('data', (data) => {
    const line = data.toString().trim();
    logs.push(`[${new Date().toISOString()}] ERROR: ${line}`);
    if (logs.length > 500) logs.shift();
  });

  child.on('exit', (code) => {
    logs.push(`[${new Date().toISOString()}] Process exited with code ${code}`);
  });

  agentProcesses[agent.id] = { process: child, logs };
}

// Function to stop an agent process
function stopAgentProcess(agentId) {
  const entry = agentProcesses[agentId];
  if (entry && entry.process && !entry.process.killed) {
    entry.process.kill('SIGINT');
  }
  delete agentProcesses[agentId];
}

// Express App
const app = express();

// CORS Configuration
app.use(cors({
  origin: "*", // Update this to restrict origins if necessary
  credentials: true
}));

app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// API Endpoints

// Check Token Balance
app.get('/api/checkTokens', async (req, res) => {
  const { publicKey } = req.query;
  if (!publicKey) return res.status(400).json({ error: 'Missing publicKey' });

  const hasTokens = await checkUserTokenBalance(publicKey);
  if (hasTokens) {
    if (!usersData[publicKey]) {
      usersData[publicKey] = { agents: [] };
    }
    return res.json({ eligible: true });
  } else {
    return res.json({ eligible: false });
  }
});

// Create Agent
app.post('/api/createAgent', (req, res) => {
  const { publicKey, email, username, password, character } = req.body;
  if (!publicKey || !email || !username || !password || !character) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });
  if (user.agents.length >= 3) return res.status(400).json({ error: 'Max agents reached' });

  const agentId = uuidv4();
  const newAgent = { id: agentId, email, username, password, character, running: false, logs: [] };
  user.agents.push(newAgent);
  return res.json({ success: true, agent: newAgent });
});

// Update Agent
app.post('/api/updateAgent', (req, res) => {
  const { publicKey, agentId, email, username, password, character } = req.body;
  if (!publicKey || !agentId) return res.status(400).json({ error: 'Missing publicKey or agentId' });

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });

  const agent = user.agents.find(a => a.id === agentId);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  if (email) agent.email = email;
  if (username) agent.username = username;
  if (password) agent.password = password;
  if (character) agent.character = character;

  return res.json({ success: true, agent });
});

// Delete Agent
app.post('/api/deleteAgent', (req, res) => {
  const { publicKey, agentId } = req.body;
  if (!publicKey || !agentId) return res.status(400).json({ error: 'Missing publicKey or agentId' });

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });

  const idx = user.agents.findIndex(a => a.id === agentId);
  if (idx === -1) return res.status(404).json({ error: 'Agent not found' });

  const agent = user.agents[idx];
  if (agent.running) {
    stopAgentProcess(agentId);
  }

  user.agents.splice(idx, 1);
  return res.json({ success: true });
});

// Start Agent
app.post('/api/startAgent', (req, res) => {
  const { publicKey, agentId } = req.body;
  if (!publicKey || !agentId) return res.status(400).json({ error: 'Missing publicKey or agentId' });

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });

  const agent = user.agents.find(a => a.id === agentId);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  if (agent.running) return res.json({ success: true, message: 'Already running' });

  agent.running = true;
  agent.logs.push(`[${new Date().toISOString()}] Agent started.`);
  startAgentProcess(agent);
  return res.json({ success: true });
});

// Stop Agent
app.post('/api/stopAgent', (req, res) => {
  const { publicKey, agentId } = req.body;
  if (!publicKey || !agentId) return res.status(400).json({ error: 'Missing publicKey or agentId' });

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });

  const agent = user.agents.find(a => a.id === agentId);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  if (!agent.running) return res.json({ success: true, message: 'Already stopped' });

  agent.running = false;
  agent.logs.push(`[${new Date().toISOString()}] Agent stopped.`);
  stopAgentProcess(agentId);

  return res.json({ success: true });
});

// Get Agents
app.get('/api/getAgents', (req, res) => {
  const { publicKey } = req.query;
  if (!publicKey) return res.status(400).json({ error: 'Missing publicKey' });

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });

  return res.json({ agents: user.agents });
});

// Get Agent Logs
app.get('/api/getAgentLogs', (req, res) => {
  const { publicKey, agentId } = req.query;
  if (!publicKey || !agentId) return res.status(400).json({ error: 'Missing publicKey or agentId' });

  const user = usersData[publicKey];
  if (!user) return res.status(403).json({ error: 'Not authorized' });

  const agent = user.agents.find(a => a.id === agentId);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  return res.json({ logs: agent.logs });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Backend running on http://localhost:${PORT}`);
});
