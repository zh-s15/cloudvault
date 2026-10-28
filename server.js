require("dotenv").config();

const express = require("express");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand
} = require("@aws-sdk/client-s3");

const app = express();
const PORT = process.env.PORT || 3000;
const BLOCK_SIZE = 64 * 1024;
const MAX_FILE_SIZE = 20 * 1024 * 1024;

// CORS configuration: allow the deployed CloudVault frontend
const allowedOrigins = [
  "https://cloudvault-ws.onrender.com"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type"
    );
    res.setHeader(
      "Access-Control-Expose-Headers",
      "Content-Disposition"
    );
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const {
  AWS_REGION,
  S3_BUCKET,
  ENCRYPTION_MASTER_KEY
} = process.env;

if (!AWS_REGION || !S3_BUCKET || !ENCRYPTION_MASTER_KEY) {
  throw new Error(
    "Missing AWS_REGION, S3_BUCKET, or ENCRYPTION_MASTER_KEY in .env"
  );
}

if (!/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_MASTER_KEY)) {
  throw new Error(
    "ENCRYPTION_MASTER_KEY must be exactly 64 hexadecimal characters."
  );
}

const masterKey = Buffer.from(ENCRYPTION_MASTER_KEY, "hex");
const s3 = new S3Client({ region: AWS_REGION });

// Serve frontend files if present
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE }
});

function deriveFileKey(fileId) {
  return crypto
    .createHmac("sha256", masterKey)
    .update(fileId)
    .digest();
}

function safeFilename(name) {
  return path.basename(name).replace(/["\\\r\n]/g, "_");
}

async function readS3Object(key) {
  const result = await s3.send(
    new GetObjectCommand({
      Bucket: S3_BUCKET,
      Key: key
    })
  );

  return Buffer.from(await result.Body.transformToByteArray());
}

// Upload, split, encrypt, and store file blocks in S3
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "Please select a file."
      });
    }

    const fileId = crypto.randomUUID();
    const fileKey = deriveFileKey(fileId);
    const blocks = [];
    const totalBlocks = Math.ceil(
      req.file.buffer.length / BLOCK_SIZE
    );

    for (
      let offset = 0, index = 0;
      offset < req.file.buffer.length;
      offset += BLOCK_SIZE, index++
    ) {
      const plainBlock = req.file.buffer.subarray(
        offset,
        Math.min(offset + BLOCK_SIZE, req.file.buffer.length)
      );

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        fileKey,
        iv
      );

      const encrypted = Buffer.concat([
        cipher.update(plainBlock),
        cipher.final()
      ]);

      const authTag = cipher.getAuthTag();
      const objectKey =
        `files/${fileId}/block-${String(index).padStart(6, "0")}.bin`;

      await s3.send(
        new PutObjectCommand({
          Bucket: S3_BUCKET,
          Key: objectKey,
          Body: encrypted,
          ContentType: "application/octet-stream",
          ServerSideEncryption: "AES256"
        })
      );

      blocks.push({
        key: objectKey,
        iv: iv.toString("base64"),
        authTag: authTag.toString("base64")
      });
    }

    const manifest = {
      fileId,
      fileName: safeFilename(req.file.originalname),
      originalSize: req.file.size,
      blockSize: BLOCK_SIZE,
      totalBlocks,
      blocks
    };

    await s3.send(
      new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: `files/${fileId}/manifest.json`,
        Body: JSON.stringify(manifest),
        ContentType: "application/json",
        ServerSideEncryption: "AES256"
      })
    );

    res.json({
      message: "File split, encrypted, and stored in Amazon S3!",
      fileId,
      fileName: manifest.fileName,
      originalSize: manifest.originalSize,
      blockSize: BLOCK_SIZE,
      totalBlocks
    });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({
      error: "Upload failed. Check AWS configuration and bucket permissions."
    });
  }
});

// Download encrypted blocks without decrypting them.
// Package format: CVAULT1 header, manifest length + JSON,
// followed by each encrypted block's length and bytes.
app.get("/api/download-encrypted/:id", async (req, res) => {
  try {
    const fileId = req.params.id;

    if (!/^[0-9a-f-]{36}$/i.test(fileId)) {
      return res.status(400).json({
        error: "Invalid file ID."
      });
    }

    let manifest;

    try {
      const data = await readS3Object(
        `files/${fileId}/manifest.json`
      );
      manifest = JSON.parse(data.toString("utf8"));
    } catch (error) {
      if (
        error.name === "NoSuchKey" ||
        error.name === "NotFound"
      ) {
        return res.status(404).json({
          error: "File not found in S3."
        });
      }
      throw error;
    }

    if (
      manifest.fileId !== fileId ||
      !Array.isArray(manifest.blocks) ||
      !Number.isInteger(manifest.totalBlocks) ||
      manifest.totalBlocks < 1 ||
      manifest.totalBlocks > Math.ceil(MAX_FILE_SIZE / BLOCK_SIZE) ||
      manifest.blocks.length !== manifest.totalBlocks
    ) {
      return res.status(500).json({
        error: "Stored file manifest is invalid."
      });
    }

    const manifestBuffer = Buffer.from(
      JSON.stringify(manifest),
      "utf8"
    );

    const manifestLength = Buffer.alloc(4);
    manifestLength.writeUInt32BE(manifestBuffer.length);

    const parts = [
      Buffer.from("CVAULT1\n", "ascii"),
      manifestLength,
      manifestBuffer
    ];

    // Fetch each encrypted block as stored in S3.
    // This route never decrypts the block contents.
    for (let index = 0; index < manifest.blocks.length; index++) {
      const block = manifest.blocks[index];

      const expectedKey =
        `files/${fileId}/block-${String(index).padStart(6, "0")}.bin`;

      if (
        !block ||
        block.key !== expectedKey ||
        typeof block.iv !== "string" ||
        typeof block.authTag !== "string"
      ) {
        return res.status(500).json({
          error: "Stored block metadata is invalid."
        });
      }

      const encryptedBlock = await readS3Object(expectedKey);

      const blockLength = Buffer.alloc(4);
      blockLength.writeUInt32BE(encryptedBlock.length);

      parts.push(blockLength, encryptedBlock);
    }

    const encryptedPackage = Buffer.concat(parts);
    const downloadName =
      `${safeFilename(manifest.fileName) || "cloudvault-file"}.cvault`;

    res.setHeader(
      "Content-Type",
      "application/octet-stream"
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${downloadName}"`
    );
    res.setHeader(
      "Content-Length",
      encryptedPackage.length
    );

    return res.send(encryptedPackage);
  } catch (error) {
    console.error("Encrypted download error:", error);
    return res.status(500).json({
      error: "Encrypted download failed. Check the server configuration."
    });
  }
});

// Retrieve, decrypt, and reconstruct the original file
app.get("/api/download/:id", async (req, res) => {
  try {
    const fileId = req.params.id;

    if (!/^[0-9a-f-]{36}$/i.test(fileId)) {
      return res.status(400).json({
        error: "Invalid file ID."
      });
    }

    let manifest;

    try {
      const data = await readS3Object(
        `files/${fileId}/manifest.json`
      );
      manifest = JSON.parse(data.toString("utf8"));
    } catch (error) {
      if (
        error.name === "NoSuchKey" ||
        error.name === "NotFound"
      ) {
        return res.status(404).json({
          error: "File not found in S3."
        });
      }
      throw error;
    }

    if (
      manifest.fileId !== fileId ||
      !Array.isArray(manifest.blocks) ||
      manifest.blocks.length !== manifest.totalBlocks
    ) {
      return res.status(500).json({
        error: "Stored file manifest is invalid."
      });
    }

    const fileKey = deriveFileKey(fileId);
    const decryptedBlocks = [];

    for (const block of manifest.blocks) {
      const encrypted = await readS3Object(block.key);

      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        fileKey,
        Buffer.from(block.iv, "base64")
      );

      decipher.setAuthTag(
        Buffer.from(block.authTag, "base64")
      );

      decryptedBlocks.push(
        Buffer.concat([
          decipher.update(encrypted),
          decipher.final()
        ])
      );
    }

    const original = Buffer.concat(decryptedBlocks);

    if (original.length !== manifest.originalSize) {
      return res.status(500).json({
        error: "Restored file size does not match."
      });
    }

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeFilename(manifest.fileName)}"`
    );
    res.setHeader(
      "Content-Type",
      "application/octet-stream"
    );

    return res.send(original);
  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({
      error: "Download or decryption failed. Check the server configuration."
    });
  }
});

app.listen(PORT, () => {
  console.log(`CloudVault is running at http://localhost:${PORT}`);
});
