// server.js
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/scan", (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  const command = `
    curl -I -s ${url} | grep "HTTP" &&
    curl -s -o /dev/null -w "Load Time: %{time_total}s\\n" ${url} &&
    curl -s --head ${url} | grep "Server:"
  `;

  exec(command, (error, stdout) => {
    if (error) return res.status(500).json({ error: error.message });

    res.json({ url, scanResults: stdout });
  });
});

app.listen(5000, () => console.log("Server running on port 5000"));