const express = require("express");
const cors = require("cors");
const fs = require("fs");
const crypto = require("crypto");
const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" })); // allow large content

// === FILE UNTUK HISTORY ===
const HISTORY_FILE = "./history.json";

// Pastikan history file ada
if (!fs.existsSync(HISTORY_FILE)) {
  fs.writeFileSync(HISTORY_FILE, JSON.stringify([]));
}

// ✅ Root endpoint
app.get("/", (req, res) => {
  res.send("✅ Backend USB Cleaner aktif!");
});

// ✅ Ambil history
app.get("/history", (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(HISTORY_FILE));
    res.json(data);
  } catch (err) {
    res.json([]);
  }
});

// ✅ Simpan history scan
app.post("/saveScan", (req, res) => {
  const scanData = req.body.files || [];

  const history = JSON.parse(fs.readFileSync(HISTORY_FILE));

  history.push({
    time: new Date(),
    threats: scanData
  });

  fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));

  console.log("💾 History updated:", scanData);

  res.json({ status: "saved", saved: scanData });
});

// Helper hashing content
function hashContent(byteArray) {
  return crypto
    .createHash("md5")
    .update(Buffer.from(byteArray))
    .digest("hex");
}

// ✅ Scan folder
app.post("/scanFolder", (req, res) => {
  const { files } = req.body;

  if (!files || files.length === 0) {
    return res.json({ threats: [] });
  }

  let suspicious = [];

  // 1️⃣ ekstensi berbahaya
  const extBad = files
    .filter(f =>
      f.name.endsWith(".exe") ||
      f.name.endsWith(".dll") ||
      f.name.endsWith(".inf") ||
      f.name.endsWith(".bat") ||
      f.name.endsWith(".cmd") ||
      f.name.toLowerCase().includes("autorun")
    )
    .map(f => f.name);

  suspicious.push(...extBad);

  // 2️⃣ hidden file
  const hidden = files
    .filter(f => f.name.startsWith("."))
    .map(f => f.name);

  suspicious.push(...hidden);

  // 3️⃣ duplicate berdasarkan hash isi
  const hashMap = {};
  const dupContent = [];

  files.forEach(f => {
    const h = hashContent(f.content);
    if (hashMap[h]) {
      dupContent.push(f.name);
    } else {
      hashMap[h] = f.name;
    }
  });

  suspicious.push(...dupContent);

  // hapus duplikat dalam daftar threats
  const threats = [...new Set(suspicious)];

  console.log("🧪 Scan result:", threats);

  res.json({ threats });
});

// ✅ Dummy Scan Endpoint
app.get("/scan", (req, res) => {
  res.json({
    status: "ok",
    files: ["virus.exe", "autorun.inf"]
  });
});

// ✅ Clear History
app.post("/clearHistory", (req, res) => {
  fs.writeFileSync(HISTORY_FILE, JSON.stringify([]));
  console.log("🧹 History cleared!");
  res.json({ status: "cleared" });
});

// ✅ Start server (IMPORTANT for Render)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
