const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");

const app = express();
app.use(cors());

// API Key authentication
const API_KEY = process.env.API_KEY || "your-secure-api-key";

const authenticate = (req, res, next) => {
  const providedApiKey = req.headers["x-api-key"];
  if (!providedApiKey || providedApiKey !== API_KEY) {
    return res.status(403).json({ error: "Forbidden: Invalid API Key" });
  }
  next();
};

// WHOIS Lookup Endpoint
app.get("/whois", authenticate, (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: "Domain is required" });
  }

  console.log(`🔍 Running WHOIS lookup for: ${domain}`);

  exec(`whois -H ${domain}`, { timeout: 15000 }, (error, stdout, stderr) => {
    if (error) {
      console.error(`❌ WHOIS Error: ${stderr || error.message}`);
      return res.status(500).json({ error: stderr.trim() || "WHOIS lookup failed" });
    }
    res.json({ domain, whois: stdout.trim() });
  });
});

// Subfinder Subdomain Enumeration Endpoint
app.get("/scan", authenticate, (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: "Domain is required" });
  }

  console.log(`🔍 Running Subfinder scan for: ${domain}`);

  exec(`subfinder -d ${domain} -silent`, { timeout: 120000 }, (error, stdout, stderr) => {
    if (error) {
      console.error(`❌ Subfinder Error: ${stderr || error.message}`);
      return res.status(500).json({ error: stderr.trim() || "Subfinder execution failed" });
    }

    const subdomains = stdout.split("\n").filter((line) => line).map((name) => ({
      name,
      timestamp: new Date().toISOString(),
    }));

    res.json({ domain, found: subdomains.length, subdomains });
  });
});

// Start the server on port 8080
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`✅ API running on port ${PORT}`));
