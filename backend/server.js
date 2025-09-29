const express = require("express")
const http = require("http")
const { Server } = require("socket.io")
const multer = require("multer")
const fs = require("fs")
const path = require("path")
const crypto = require("crypto")
const CRC32 = require("crc-32")
const cors = require("cors")
const bodyParser = require("body-parser")
const bcrypt = require("bcrypt")
const session = require("express-session")
const db = require("./db")

const APP_ROOT = __dirname
const UPLOAD_ROOT = path.join(APP_ROOT, "uploads")
if (!fs.existsSync(UPLOAD_ROOT)) fs.mkdirSync(UPLOAD_ROOT, { recursive: true })

const app = express()

// Dev-friendly CORS
app.use(cors({ origin: true, credentials: true }))
app.use(bodyParser.json({ limit: "200mb" }))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(
  session({
    secret: "lightshare-demo-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 3600 * 1000, httpOnly: true, sameSite: "lax" },
  }),
)

app.use("/", express.static(path.join(__dirname, "public")))

app.get("/api/auth/check", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user })
  } else {
    res.json({ loggedIn: false })
  }
})

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" })
  }

  try {
    const user = await findUser(username)
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    req.session.user = { id: user.id, username: user.username }
    res.json({ success: true, user: { username: user.username } })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Login failed" })
  }
})

app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" })
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" })
  }

  try {
    const existingUser = await findUser(username)
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = await createUser(username, hashedPassword)

    req.session.user = { id: user.id, username: user.username }
    res.json({ success: true, user: { username: user.username } })
  } catch (error) {
    console.error("Signup error:", error)
    res.status(500).json({ error: "Signup failed" })
  }
})

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" })
    }
    res.json({ success: true })
  })
})

const server = http.createServer(app)
const io = new Server(server, {
  cors: { origin: (origin, cb) => cb(null, true), methods: ["GET", "POST", "DELETE"], credentials: true },
})

const storage = multer.memoryStorage()
const upload = multer({ storage })

// In-memory stores
const WORKSPACES = {} // room -> { creator, members:Set(username), transfers:Set, active }
const TRANSFERS = {} // id -> transfer info
const USERSOCK = {} // username -> socketId
const SOCKET_ROOMS = {} // socketId -> Set(room)
const ACK_TIMERS = {} // transferId -> timeout

// Helpers
function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true })
}

function normalizeName(name) {
  if (!name) return ""
  const trimmed = ("" + name).trim()
  return trimmed.split(":", 1)[0].trim().toLowerCase()
}

function encryptAesGcm(buffer) {
  const key = crypto.randomBytes(32)
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv)
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()])
  const tag = cipher.getAuthTag()
  return {
    payloadB64: Buffer.concat([encrypted, tag]).toString("base64"),
    keyB64: key.toString("base64"),
    ivB64: iv.toString("base64"),
  }
}

function decryptAesGcm(payloadB64, keyB64, ivB64) {
  const payload = Buffer.from(payloadB64, "base64")
  const key = Buffer.from(keyB64, "base64")
  const iv = Buffer.from(ivB64, "base64")
  const tag = payload.slice(payload.length - 16)
  const encrypted = payload.slice(0, payload.length - 16)
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(encrypted), decipher.final()])
}

function encryptPdfWithCRC32(buffer) {
  const crc = CRC32.buf(buffer)
  const key = crypto.randomBytes(32) // increased key size for AES-256
  const iv = crypto.randomBytes(16) // added IV for security
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv) // replaced deprecated createCipher with createCipheriv
  let encrypted = cipher.update(buffer)
  encrypted = Buffer.concat([encrypted, cipher.final()])

  return {
    encrypted: encrypted.toString("base64"),
    key: key.toString("base64"),
    iv: iv.toString("base64"), // added IV to return object
    crc: crc,
    originalSize: buffer.length,
  }
}

function decryptPdfWithCRC32(encryptedB64, keyB64, ivB64, originalCrc, originalSize) {
  const encrypted = Buffer.from(encryptedB64, "base64")
  const key = Buffer.from(keyB64, "base64")
  const iv = Buffer.from(ivB64, "base64") // decode IV from base64
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv) // replaced deprecated createDecipher with createDecipheriv
  let decrypted = decipher.update(encrypted)
  decrypted = Buffer.concat([decrypted, decipher.final()])

  // Verify CRC32
  const calculatedCrc = CRC32.buf(decrypted)
  if (calculatedCrc !== originalCrc || decrypted.length !== originalSize) {
    throw new Error("CRC32 verification failed - data corrupted")
  }

  return decrypted
}

function hammingEncodeBuffer(buf) {
  const out = new Uint8Array(buf.length * 2)
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]
    out[i * 2] = encodeNibbleTo7((b >> 4) & 0xf)
    out[i * 2 + 1] = encodeNibbleTo7(b & 0xf)
  }
  return out
}

function hammingDecodeBuffer(encBuf) {
  const out = Buffer.alloc(encBuf.length / 2)
  for (let i = 0; i < out.length; i++) {
    const hi = decode7ToNibble(encBuf[i * 2]).nibble
    const lo = decode7ToNibble(encBuf[i * 2 + 1]).nibble
    out[i] = (hi << 4) | lo
  }
  return out
}

function startAckTimer(id) {
  ACK_TIMERS[id] = setTimeout(
    () => {
      console.log("ACK timeout, retransmit", id)
      retransmit(id)
    },
    2 * 60 * 1000,
  )
}
function clearAckTimer(id) {
  if (ACK_TIMERS[id]) {
    clearTimeout(ACK_TIMERS[id])
    delete ACK_TIMERS[id]
  }
}

function retransmit(id) {
  const info = TRANSFERS[id]
  if (!info) {
    console.error(`[v0] Cannot retransmit - transfer ${id} not found`)
    return
  }

  if (info.attempts >= 5) {
    console.log(`[v0] Maximum retransmission attempts reached for transfer ${id}`)
    info.status = "failed"

    // Notify sender of failure
    const senderSocket = USERSOCK[info.sender]
    if (senderSocket) {
      io.to(senderSocket).emit("transferFailed", {
        transferId: id,
        filename: info.meta.originalName,
        reason: "Maximum retransmission attempts exceeded",
      })
    }
    return
  }

  try {
    console.log(`[v0] Starting retransmission ${info.attempts + 1} for transfer ${id}`)

    const original = fs.readFileSync(path.join(info.dir, "original.bin"))
    let processed = original

    if (info.meta.ftype === "pdf") {
      const pdfEncrypted = encryptPdfWithCRC32(original)
      processed = Buffer.from(pdfEncrypted.encrypted, "base64")
      console.log(`[v0] PDF re-encrypted with CRC32: ${pdfEncrypted.crc}`)
    } else if (info.meta.ftype === "image") {
      processed = hammingEncodeBuffer(original)
      console.log(`[v0] Image re-encoded with Hamming code`)
    }

    const enc = encryptAesGcm(processed)
    fs.writeFileSync(path.join(info.dir, "encrypted.b64"), enc.payloadB64)

    info.payloadB64 = enc.payloadB64
    info.keyB64 = enc.keyB64
    info.ivB64 = enc.ivB64
    info.attempts = (info.attempts || 0) + 1
    info.status = "retransmitted"
    info.retransmittedAt = Date.now()

    const retransmitData = {
      transferId: id,
      filename: info.meta.originalName,
      sender: info.sender,
      ftype: info.meta.ftype,
      room: info.room,
      recipient: info.recipient,
      retransmit: true,
      attempt: info.attempts,
    }

    if (info.recipient === "all") {
      io.to(info.room).emit("fileIncoming", retransmitData)
      console.log(`[v0] Retransmitted to all users in room ${info.room}`)
    } else {
      if (USERSOCK[info.recipient]) {
        io.to(USERSOCK[info.recipient]).emit("fileIncoming", retransmitData)
        console.log(`[v0] Retransmitted to user ${info.recipient}`)
      }
    }

    if (info.attempts < 5) {
      startAckTimer(id)
    }
  } catch (e) {
    console.error(`[v0] Retransmission error for transfer ${id}:`, e)
    info.status = "retransmit_failed"
    info.lastError = e.message
  }
}

function createUser(username, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run("INSERT INTO users (username,password) VALUES (?,?)", [username, passwordHash], function (err) {
      if (err) return reject(err)
      resolve({ id: this.lastID, username })
    })
  })
}

function findUser(username) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
      if (err) return reject(err)
      resolve(row)
    })
  })
}

function createWorkspace(name, creator) {
  return new Promise((resolve, reject) => {
    const normalizedName = normalizeName(name)
    db.run(
      "INSERT INTO workspaces (name, normalized_name, creator) VALUES (?, ?, ?)",
      [name, normalizedName, creator],
      function (err) {
        if (err) {
          if (err.code === "SQLITE_CONSTRAINT") {
            return reject(new Error("Workspace name already exists"))
          }
          return reject(err)
        }

        // Add creator as first member
        db.run(
          "INSERT INTO workspace_members (workspace_id, username) VALUES (?, ?)",
          [this.lastID, creator],
          (memberErr) => {
            if (memberErr) return reject(memberErr)
            resolve({ id: this.lastID, name, creator })
          },
        )
      },
    )
  })
}

function findWorkspace(name) {
  return new Promise((resolve, reject) => {
    const normalizedName = normalizeName(name)
    db.get("SELECT * FROM workspaces WHERE normalized_name = ? AND active = 1", [normalizedName], (err, row) => {
      if (err) return reject(err)
      resolve(row)
    })
  })
}

function addWorkspaceMember(workspaceId, username) {
  return new Promise((resolve, reject) => {
    db.run(
      "INSERT OR IGNORE INTO workspace_members (workspace_id, username) VALUES (?, ?)",
      [workspaceId, username],
      function (err) {
        if (err) return reject(err)
        resolve(this.changes > 0)
      },
    )
  })
}

function getWorkspaceMembers(workspaceId) {
  return new Promise((resolve, reject) => {
    db.all("SELECT username FROM workspace_members WHERE workspace_id = ?", [workspaceId], (err, rows) => {
      if (err) return reject(err)
      resolve(rows.map((row) => row.username))
    })
  })
}

function deleteWorkspace(name, creator) {
  return new Promise((resolve, reject) => {
    const normalizedName = normalizeName(name)
    db.run(
      "UPDATE workspaces SET active = 0 WHERE normalized_name = ? AND creator = ? AND active = 1",
      [normalizedName, creator],
      function (err) {
        if (err) return reject(err)
        resolve(this.changes > 0)
      },
    )
  })
}

app.post("/api/workspace/create", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" })

  const { name } = req.body
  if (!name || !name.trim()) return res.status(400).json({ error: "Workspace name required" })

  try {
    const existingWorkspace = await findWorkspace(name)
    if (existingWorkspace) {
      return res.status(409).json({ error: "Workspace name already exists" })
    }

    const workspace = await createWorkspace(name.trim(), req.session.user.username)
    res.json({ success: true, workspace })
  } catch (error) {
    console.error("Create workspace error:", error)
    res.status(500).json({ error: error.message })
  }
})

app.post("/api/workspace/join", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" })

  const { name } = req.body
  if (!name || !name.trim()) return res.status(400).json({ error: "Workspace name required" })

  try {
    const workspace = await findWorkspace(name)
    if (!workspace) {
      return res.status(404).json({ error: "Workspace not found" })
    }

    await addWorkspaceMember(workspace.id, req.session.user.username)
    res.json({ success: true, workspace })
  } catch (error) {
    console.error("Join workspace error:", error)
    res.status(500).json({ error: error.message })
  }
})

app.get("/api/workspace/:name/members", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" })

  try {
    const workspace = await findWorkspace(req.params.name)
    if (!workspace) {
      return res.status(404).json({ error: "Workspace not found" })
    }

    const members = await getWorkspaceMembers(workspace.id)
    res.json({ members, creator: workspace.creator })
  } catch (error) {
    console.error("Get members error:", error)
    res.status(500).json({ error: error.message })
  }
})

app.delete("/api/workspace/:name", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" })

  try {
    const deleted = await deleteWorkspace(req.params.name, req.session.user.username)
    if (!deleted) {
      return res.status(403).json({ error: "Only workspace creator can delete workspace" })
    }

    // Remove from in-memory store and disconnect all users
    const normalizedName = normalizeName(req.params.name)
    if (WORKSPACES[normalizedName]) {
      io.to(normalizedName).emit("workspaceDeleted")
      delete WORKSPACES[normalizedName]
    }

    res.json({ success: true })
  } catch (error) {
    console.error("Delete workspace error:", error)
    res.status(500).json({ error: error.message })
  }
})

app.post("/api/upload", upload.single("file"), async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" })
  if (!req.file) return res.status(400).json({ error: "No file uploaded" })

  const { room, recipient, ftype } = req.body
  if (!room) return res.status(400).json({ error: "Room required" })

  try {
    const transferId = crypto.randomUUID()
    const transferDir = path.join(UPLOAD_ROOT, transferId)
    ensureDir(transferDir)

    // Save original file
    const originalPath = path.join(transferDir, "original.bin")
    fs.writeFileSync(originalPath, req.file.buffer)

    let processed = req.file.buffer
    let encryptionMeta = {}

    // Apply file-type specific encryption
    if (ftype === "pdf") {
      const pdfEncrypted = encryptPdfWithCRC32(req.file.buffer)
      processed = Buffer.from(pdfEncrypted.encrypted, "base64")
      encryptionMeta = { type: "crc32", ...pdfEncrypted }
    } else if (ftype === "image") {
      processed = hammingEncodeBuffer(req.file.buffer)
      encryptionMeta = { type: "hamming" }
    } else if (ftype === "video") {
      // Use existing AES-GCM encryption for videos
      encryptionMeta = { type: "aes-gcm" }
    }

    // Final AES-GCM encryption
    const enc = encryptAesGcm(processed)
    fs.writeFileSync(path.join(transferDir, "encrypted.b64"), enc.payloadB64)

    const transferInfo = {
      id: transferId,
      sender: req.session.user.username,
      recipient: recipient || "all",
      room,
      meta: {
        originalName: req.file.originalname,
        ftype,
        size: req.file.size,
        encryptionMeta,
      },
      dir: transferDir,
      payloadB64: enc.payloadB64,
      keyB64: enc.keyB64,
      ivB64: enc.ivB64,
      status: "pending",
      timestamp: Date.now(),
    }

    TRANSFERS[transferId] = transferInfo

    // Emit to recipients
    if (recipient === "all" || !recipient) {
      io.to(room).emit("fileIncoming", {
        transferId,
        filename: req.file.originalname,
        sender: req.session.user.username,
        ftype,
        room,
        recipient: "all",
      })
    } else {
      if (USERSOCK[recipient]) {
        io.to(USERSOCK[recipient]).emit("fileIncoming", {
          transferId,
          filename: req.file.originalname,
          sender: req.session.user.username,
          ftype,
          room,
          recipient,
        })
      }
    }

    startAckTimer(transferId)
    res.json({ success: true, transferId })
  } catch (error) {
    console.error("Upload error:", error)
    res.status(500).json({ error: error.message })
  }
})

app.get("/api/download/:transferId", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" })

  const transferId = req.params.transferId
  const info = TRANSFERS[transferId]

  if (!info) return res.status(404).json({ error: "Transfer not found" })

  try {
    console.log(`[v0] Download attempt for transfer ${transferId} by user ${req.session.user.username}`)

    // Decrypt the file
    const decrypted = decryptAesGcm(info.payloadB64, info.keyB64, info.ivB64)
    let finalData = decrypted
    let hasError = false
    let errorDetails = ""

    // Apply file-type specific decryption with error detection
    if (info.meta.ftype === "pdf") {
      try {
        finalData = decryptPdfWithCRC32(
          decrypted,
          info.meta.encryptionMeta.key,
          info.meta.encryptionMeta.iv,
          info.meta.encryptionMeta.crc,
          info.meta.encryptionMeta.originalSize,
        )
        console.log(`[v0] PDF decryption successful, CRC32 verified`)
      } catch (pdfError) {
        hasError = true
        errorDetails = `PDF decryption failed: ${pdfError.message}`
        console.error(`[v0] PDF decryption error:`, pdfError)
      }
    } else if (info.meta.ftype === "image") {
      try {
        finalData = hammingDecodeBuffer(decrypted)
        console.log(`[v0] Image Hamming decoding successful`)
      } catch (hammingError) {
        hasError = true
        errorDetails = `Hamming code correction failed: ${hammingError.message}`
        console.error(`[v0] Hamming decoding error:`, hammingError)
      }
    }

    if (!hasError && finalData.length !== info.meta.size) {
      hasError = true
      errorDetails = `Data size mismatch: expected ${info.meta.size}, got ${finalData.length}`
      console.error(`[v0] Data integrity check failed for transfer ${transferId}`)
    }

    if (hasError) {
      console.log(`[v0] Error detected, scheduling retransmission in 1 minute for transfer ${transferId}`)

      info.errorCount = (info.errorCount || 0) + 1
      info.lastError = errorDetails
      info.lastErrorTime = Date.now()

      // Don't send acknowledgment and schedule retransmission
      setTimeout(() => {
        console.log(`[v0] Initiating retransmission for transfer ${transferId} (attempt ${info.errorCount})`)
        retransmit(transferId)
      }, 60000) // 1 minute delay as requested

      return res.status(500).json({
        error: "File decryption failed - data may be corrupted",
        details: errorDetails,
        willRetransmit: true,
        retransmitIn: 60,
      })
    }

    console.log(`[v0] File download successful for transfer ${transferId}`)
    info.status = "completed"
    info.completedAt = Date.now()

    let contentType = "application/octet-stream"
    if (info.meta.ftype === "pdf") {
      contentType = "application/pdf"
    } else if (info.meta.ftype === "image") {
      // Try to determine image type from filename
      const ext = path.extname(info.meta.originalName).toLowerCase()
      if (ext === ".jpg" || ext === ".jpeg") contentType = "image/jpeg"
      else if (ext === ".png") contentType = "image/png"
      else if (ext === ".gif") contentType = "image/gif"
      else if (ext === ".webp") contentType = "image/webp"
    }

    const encodedFilename = encodeURIComponent(info.meta.originalName)
    res.setHeader("Content-Type", contentType)
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodedFilename}`)
    res.send(finalData)
  } catch (error) {
    console.error(`[v0] Unexpected download error for transfer ${transferId}:`, error)

    info.errorCount = (info.errorCount || 0) + 1
    info.lastError = error.message
    info.lastErrorTime = Date.now()

    res.status(500).json({
      error: "File decryption failed - unexpected error",
      details: error.message,
      willRetransmit: true,
      retransmitIn: 60,
    })

    // Trigger retransmission after 1 minute
    setTimeout(() => {
      console.log(`[v0] Initiating retransmission after unexpected error for transfer ${transferId}`)
      retransmit(transferId)
    }, 60000)
  }
})

io.on("connection", (socket) => {
  console.log(`[v0] Socket connected: ${socket.id}`)

  socket.on("joinRoom", async (data) => {
    const { room, username } = data
    if (!room || !username) {
      console.error(`[v0] Invalid join room data:`, data)
      return
    }

    try {
      // Verify workspace exists
      const workspace = await findWorkspace(room)
      if (!workspace) {
        console.error(`[v0] Workspace not found: ${room}`)
        socket.emit("error", { message: "Workspace not found" })
        return
      }

      socket.join(room)
      USERSOCK[username] = socket.id
      console.log(`[v0] User ${username} joined room ${room}`)

      if (!SOCKET_ROOMS[socket.id]) SOCKET_ROOMS[socket.id] = new Set()
      SOCKET_ROOMS[socket.id].add(room)

      if (!WORKSPACES[room]) {
        WORKSPACES[room] = {
          creator: workspace.creator,
          members: new Set(),
          transfers: new Set(),
          active: true,
        }
      }
      WORKSPACES[room].members.add(username)

      // Get and emit current members list
      const members = await getWorkspaceMembers(workspace.id)
      io.to(room).emit("membersUpdate", {
        members,
        creator: workspace.creator,
      })

      socket.emit("joinedRoom", { room, creator: workspace.creator })
    } catch (error) {
      console.error(`[v0] Join room error:`, error)
      socket.emit("error", { message: error.message })
    }
  })

  socket.on("fileAck", (data) => {
    const { transferId } = data
    if (TRANSFERS[transferId]) {
      console.log(`[v0] File acknowledged: ${transferId}`)
      TRANSFERS[transferId].status = "acknowledged"
      TRANSFERS[transferId].acknowledgedAt = Date.now()
      clearAckTimer(transferId)

      // Notify sender
      const senderSocket = USERSOCK[TRANSFERS[transferId].sender]
      if (senderSocket) {
        io.to(senderSocket).emit("fileAcknowledged", { transferId })
      }
    }
  })

  socket.on("disconnect", () => {
    console.log(`[v0] Socket disconnected: ${socket.id}`)

    // Clean up user socket mapping
    for (const [username, socketId] of Object.entries(USERSOCK)) {
      if (socketId === socket.id) {
        console.log(`[v0] Cleaning up user mapping: ${username}`)
        delete USERSOCK[username]
        break
      }
    }

    // Clean up room memberships
    if (SOCKET_ROOMS[socket.id]) {
      for (const room of SOCKET_ROOMS[socket.id]) {
        if (WORKSPACES[room]) {
          // Remove from members but don't delete workspace
          for (const [username, socketId] of Object.entries(USERSOCK)) {
            if (socketId === socket.id) {
              WORKSPACES[room].members.delete(username)
              break
            }
          }
        }
      }
      delete SOCKET_ROOMS[socket.id]
    }
  })
})

const PORT = process.env.PORT || 3000
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Open http://localhost:${PORT}/index.html`)
})

function encodeNibbleTo7(n) {
  const d0 = (n >> 0) & 1,
    d1 = (n >> 1) & 1,
    d2 = (n >> 2) & 1,
    d3 = (n >> 3) & 1
  const p0 = d0 ^ d1 ^ d3,
    p1 = d0 ^ d2 ^ d3,
    p2 = d1 ^ d2 ^ d3
  const bits = [p0, p1, d0, p2, d1, d2, d3]
  let val = 0
  for (let i = 0; i < 7; i++) val |= bits[i] << (6 - i)
  return val
}

function decode7ToNibble(val) {
  const bits = []
  for (let i = 6; i >= 0; i--) bits.push((val >> i) & 1)
  let [p0, p1, d0, p2, d1, d2, d3] = bits
  const s0 = p0 ^ d0 ^ d1 ^ d3,
    s1 = p1 ^ d0 ^ d2 ^ d3,
    s2 = p2 ^ d1 ^ d2 ^ d3
  const syndrome = (s0 << 2) | (s1 << 1) | s2
  if (syndrome !== 0) {
    const idx = syndrome - 1
    bits[idx] ^= 1
    ;[p0, p1, d0, p2, d1, d2, d3] = bits
  }
  return { nibble: (d3 << 3) | (d2 << 2) | (d1 << 1) | d0 }
}
