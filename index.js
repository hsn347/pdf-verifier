const express = require("express");
const axios = require("axios");
const pdf = require("pdf-parse");

const app = express();
app.use(express.json());

// ============================================================
//  🔐 BANK RECEIPT FINGERPRINT
//  Extracted from authentic bank-generated receipt (Notice.pdf)
//  Generated: 2026-04-16
// ============================================================
const BANK_FINGERPRINT = {
  // Layer 1 – PDF Technical Specification
  pdfVersion: "1.4",
  // iText 5.x is the expected generation engine
  producerPattern: /iText[®\u00ae]\s+5\.\d+\.\d+/i,
  // A4 page dimensions (595 x 842 points)
  mediaBox: { width: 595, height: 842, tolerance: 2 },
  // Binary comment marker bytes in second line (proves binary PDF)
  binaryMarkerHex: "25e2e3cfd3",

  // Layer 2 – PDF Object Structure
  objectCount: { min: 10, max: 20 },
  streamCount: { min: 4, max: 10 },
  imageXObjects: { min: 1, max: 5 },
  flatDecodeStreams: { min: 4, max: 10 },
  // DCTDecode (JPEG) must NOT be present — images are lossless
  dctDecodeAllowed: false,

  // Layer 3 – Security / Integrity Flags (must ALL be false)
  forbiddenFlags: [
    "/JavaScript",
    "/EmbeddedFiles",
    "/OpenAction",
    "/Encrypt",
    "/AcroForm",
    "/AA ",           // additional-actions
    "/Launch",
    "/URI ",
  ],

  // Layer 4 – Text Content Fingerprint
  requiredPhrases: [
    "إشعار سحب",
    "هذا الإشعار آلي ولايحتاج إلى ختم أو توقيع",
  ],
  // Reference number pattern from iText systems
  referencePattern: /Omq[A-Za-z0-9]{10,20}/,
  amountPattern: /\[\s*\d+\s*\]/,          // e.g. [ 100 ]
  datePattern: /\d{4}\/\d{2}\/\d{2}/,      // e.g. 2026/01/31
  textLength: { min: 150, max: 1500 },
  pageCount: { min: 1, max: 1 },

  // Layer 5 – Metadata Consistency
  // CreationDate and ModDate must match (auto-generated = same timestamp)
  modDateMustMatchCreation: true,

  // Layer 6 – File Size Range (authentic receipts are compressed images + text)
  fileSize: { minKB: 50, maxKB: 600 },

  // Layer 7 – Compression Structure
  colorSpaceObjects: { min: 1, max: 6 },
};

// ============================================================
//  Helper – read raw PDF buffer without fully parsing
// ============================================================
function analyzeRawPdf(buf) {
  const raw = buf.toString("binary");

  const versionMatch = raw.match(/%PDF-(\d+\.\d+)/);
  const producerMatch = raw.match(/Producer[\s\S]{0,5}\(([^)]{1,120})\)/);
  const mediaBoxMatch = raw.match(/\/MediaBox\s*\[([^\]]+)\]/);
  const creationMatch = raw.match(/CreationDate[\s\S]{0,5}\(D:(\d{8})/);
  const modMatch = raw.match(/ModDate[\s\S]{0,5}\(D:(\d{8})/);
  const binaryLine = Buffer.from(raw.slice(5, 14), "binary").toString("hex");

  const objCount = (raw.match(/\d+ \d+ obj/g) || []).length;
  const streamCount = (raw.match(/\bstream\b/g) || []).length;
  const imageCount = (raw.match(/\/Subtype\s*\/Image/g) || []).length;
  const flateCount = (raw.match(/\/FlateDecode/g) || []).length;
  const dctCount = (raw.match(/\/DCTDecode/g) || []).length;
  const colorSpaceCount = (raw.match(/\/ColorSpace/g) || []).length;

  const flagsFound = BANK_FINGERPRINT.forbiddenFlags.filter((f) =>
    raw.includes(f)
  );

  let mediaBoxWidth = null;
  let mediaBoxHeight = null;
  if (mediaBoxMatch) {
    const parts = mediaBoxMatch[1].trim().split(/\s+/).map(Number);
    if (parts.length >= 4) {
      mediaBoxWidth = parts[2] - parts[0];
      mediaBoxHeight = parts[3] - parts[1];
    }
  }

  return {
    pdfVersion: versionMatch ? versionMatch[1] : null,
    producer: producerMatch ? producerMatch[1] : null,
    mediaBoxWidth,
    mediaBoxHeight,
    binaryLine,
    objCount,
    streamCount,
    imageCount,
    flateCount,
    dctCount,
    colorSpaceCount,
    flagsFound,
    creationDatePrefix: creationMatch ? creationMatch[1] : null,
    modDatePrefix: modMatch ? modMatch[1] : null,
  };
}

// ============================================================
//  Core Verification Logic – 7 Layers
// ============================================================
function verifyPdf(buf, parsedData) {
  const raw = analyzeRawPdf(buf);
  const { text, info, numpages } = parsedData;
  const fp = BANK_FINGERPRINT;

  const results = [];
  let totalScore = 0;

  // ── LAYER 1: PDF Technical Specification ──────────────────
  const layer1 = { name: "PDF Technical Specification", checks: [], passed: 0, total: 0 };

  function chk(layerObj, label, pass, detail) {
    layerObj.total++;
    layerObj.checks.push({ label, pass, detail });
    if (pass) layerObj.passed++;
  }

  chk(layer1, "PDF Version 1.4", raw.pdfVersion === fp.pdfVersion, `Found: ${raw.pdfVersion}`);
  chk(layer1, "iText 5.x Producer", fp.producerPattern.test(raw.producer || ""), `Found: ${raw.producer}`);

  const widthOk = raw.mediaBoxWidth !== null &&
    Math.abs(raw.mediaBoxWidth - fp.mediaBox.width) <= fp.mediaBox.tolerance;
  const heightOk = raw.mediaBoxHeight !== null &&
    Math.abs(raw.mediaBoxHeight - fp.mediaBox.height) <= fp.mediaBox.tolerance;
  chk(layer1, "A4 Page Dimensions (595×842)", widthOk && heightOk,
    `Found: ${raw.mediaBoxWidth}×${raw.mediaBoxHeight}`);
  chk(layer1, "Binary PDF Marker", raw.binaryLine.includes(fp.binaryMarkerHex),
    `Hex: ${raw.binaryLine}`);

  results.push(layer1);

  // ── LAYER 2: PDF Object Structure ─────────────────────────
  const layer2 = { name: "PDF Object Structure", checks: [], passed: 0, total: 0 };

  chk(layer2, "Object Count Range",
    raw.objCount >= fp.objectCount.min && raw.objCount <= fp.objectCount.max,
    `Found: ${raw.objCount} (expected ${fp.objectCount.min}–${fp.objectCount.max})`);
  chk(layer2, "Stream Count Range",
    raw.streamCount >= fp.streamCount.min && raw.streamCount <= fp.streamCount.max,
    `Found: ${raw.streamCount}`);
  chk(layer2, "Image XObjects Count",
    raw.imageCount >= fp.imageXObjects.min && raw.imageCount <= fp.imageXObjects.max,
    `Found: ${raw.imageCount}`);
  chk(layer2, "FlateDecode Streams",
    raw.flateCount >= fp.flatDecodeStreams.min && raw.flateCount <= fp.flatDecodeStreams.max,
    `Found: ${raw.flateCount}`);
  chk(layer2, "No JPEG (DCTDecode) Streams",
    fp.dctDecodeAllowed ? true : raw.dctCount === 0,
    `Found: ${raw.dctCount}`);

  results.push(layer2);

  // ── LAYER 3: Security & Integrity Flags ───────────────────
  const layer3 = { name: "Security & Integrity Flags", checks: [], passed: 0, total: 0 };

  chk(layer3, "No Forbidden PDF Features",
    raw.flagsFound.length === 0,
    raw.flagsFound.length > 0 ? `Forbidden flags found: ${raw.flagsFound.join(", ")}` : "Clean");
  chk(layer3, "No Encryption", !info?.IsEncrypted, `Encrypted: ${!!info?.IsEncrypted}`);
  chk(layer3, "No XFA Form", !info?.IsXFAPresent, `XFA: ${info?.IsXFAPresent}`);
  chk(layer3, "No AcroForm", !info?.IsAcroFormPresent, `AcroForm: ${info?.IsAcroFormPresent}`);
  // Valid PDF magic bytes
  chk(layer3, "Valid PDF Magic Bytes (%PDF)",
    buf.slice(0, 4).toString("ascii") === "%PDF", "Header check");

  results.push(layer3);

  // ── LAYER 4: Text Content & Pattern Matching ──────────────
  const layer4 = { name: "Text Content Fingerprint", checks: [], passed: 0, total: 0 };

  for (const phrase of fp.requiredPhrases) {
    chk(layer4, `Required phrase: "${phrase}"`, text.includes(phrase), "");
  }
  const refMatch = text.match(fp.referencePattern);
  chk(layer4, "Reference Number (OmqXXXX...)", !!refMatch,
    refMatch ? `Found: ${refMatch[0]}` : "Not found");
  chk(layer4, "Amount in Brackets [ N ]", fp.amountPattern.test(text),
    text.match(fp.amountPattern)?.[0] || "Not found");
  chk(layer4, "Date Format (YYYY/MM/DD)", fp.datePattern.test(text),
    text.match(fp.datePattern)?.[0] || "Not found");
  chk(layer4, "Text Length In Range",
    text.length >= fp.textLength.min && text.length <= fp.textLength.max,
    `Length: ${text.length}`);
  chk(layer4, "Page Count = 1",
    numpages >= fp.pageCount.min && numpages <= fp.pageCount.max,
    `Pages: ${numpages}`);

  results.push(layer4);

  // ── LAYER 5: Metadata Consistency ─────────────────────────
  const layer5 = { name: "Metadata Consistency", checks: [], passed: 0, total: 0 };

  chk(layer5, "CreationDate Present", !!raw.creationDatePrefix,
    `CreationDate: ${raw.creationDatePrefix}`);
  chk(layer5, "ModDate Present", !!raw.modDatePrefix,
    `ModDate: ${raw.modDatePrefix}`);
  chk(layer5, "CreationDate == ModDate (auto-generated)",
    fp.modDateMustMatchCreation
      ? raw.creationDatePrefix === raw.modDatePrefix
      : true,
    `Creation: ${raw.creationDatePrefix} / Mod: ${raw.modDatePrefix}`);
  chk(layer5, "Producer Field Present", !!raw.producer, `Producer: ${raw.producer}`);

  results.push(layer5);

  // ── LAYER 6: File Size Plausibility ───────────────────────
  const layer6 = { name: "File Size Plausibility", checks: [], passed: 0, total: 0 };

  const fileSizeKB = buf.length / 1024;
  chk(layer6, `File Size ${fp.fileSize.minKB}–${fp.fileSize.maxKB} KB`,
    fileSizeKB >= fp.fileSize.minKB && fileSizeKB <= fp.fileSize.maxKB,
    `Size: ${fileSizeKB.toFixed(1)} KB`);

  results.push(layer6);

  // ── LAYER 7: Compression Structure ────────────────────────
  const layer7 = { name: "Compression Structure", checks: [], passed: 0, total: 0 };

  chk(layer7, "ColorSpace Objects Present",
    raw.colorSpaceCount >= fp.colorSpaceObjects.min &&
    raw.colorSpaceCount <= fp.colorSpaceObjects.max,
    `Found: ${raw.colorSpaceCount}`);
  chk(layer7, "FlateDecode is Primary Compression", raw.flateCount > raw.dctCount,
    `FlateDecode: ${raw.flateCount} vs DCT: ${raw.dctCount}`);
  chk(layer7, "Has Embedded Images", raw.imageCount >= 1,
    `Images: ${raw.imageCount}`);

  results.push(layer7);

  // ── SCORING ──────────────────────────────────────────────
  // Weight each layer equally, fail if any critical layer fails entirely
  let weightedScore = 0;
  let totalChecks = 0;
  let passedChecks = 0;
  const layerSummaries = [];

  for (const layer of results) {
    totalChecks += layer.total;
    passedChecks += layer.passed;
    const layerPct = layer.total > 0 ? (layer.passed / layer.total) * 100 : 100;
    weightedScore += layerPct;
    layerSummaries.push({
      layer: layer.name,
      passed: layer.passed,
      total: layer.total,
      score: Math.round(layerPct),
      checks: layer.checks,
    });
  }

  const overallScore = Math.round(weightedScore / results.length);

  // Hard failure: critical layers that must score 100%
  const criticalLayers = ["Security & Integrity Flags", "Text Content Fingerprint"];
  const criticalFailed = layerSummaries.filter(
    (l) => criticalLayers.includes(l.layer) && l.score < 100
  );

  const isValid = overallScore >= 80 && criticalFailed.length === 0;

  // Extract structured data from text
  const extractedRef = text.match(fp.referencePattern)?.[0] || null;
  const extractedAmount = text.match(fp.amountPattern)?.[0]?.replace(/[\[\]\s]/g, "") || null;
  const extractedDate = text.match(fp.datePattern)?.[0] || null;
  // Receipt number: format 17-XXXXXX
  const receiptNoMatch = text.match(/(\d{2}-\d{6,})/);
  const extractedReceiptNo = receiptNoMatch ? receiptNoMatch[1] : null;

  return {
    valid: isValid,
    confidence: overallScore,
    criticalFailures: criticalFailed.map((l) => l.layer),
    layers: layerSummaries,
    data: {
      referenceNumber: extractedRef,
      amount: extractedAmount,
      date: extractedDate,
      receiptNumber: extractedReceiptNo,
      producer: raw.producer,
      pageCount: numpages,
      fileSizeKB: Math.round(fileSizeKB * 10) / 10,
      rawText: text.trim(),
    },
  };
}

// ============================================================
//  Express Routes
// ============================================================
app.post("/verify", async (req, res) => {
  try {
    const { file_url } = req.body;

    if (!file_url) {
      return res.status(400).json({ error: "file_url مطلوب" });
    }

    // Download PDF
    let response;
    try {
      response = await axios.get(file_url, {
        responseType: "arraybuffer",
        timeout: 30000,
        maxContentLength: 10 * 1024 * 1024, // 10 MB max
      });
    } catch (downloadErr) {
      return res.status(400).json({
        error: "فشل تحميل الملف",
        detail: downloadErr.message,
      });
    }

    const buf = Buffer.from(response.data);

    // Quick magic-bytes check before full parse
    if (buf.slice(0, 4).toString("ascii") !== "%PDF") {
      return res.status(422).json({
        valid: false,
        error: "الملف ليس PDF صحيحاً",
        confidence: 0,
      });
    }

    // Full PDF parse
    let parsedData;
    try {
      parsedData = await pdf(buf);
    } catch (parseErr) {
      return res.status(422).json({
        valid: false,
        error: "تعذّر قراءة محتوى PDF",
        detail: parseErr.message,
        confidence: 0,
      });
    }

    // Run all 7 verification layers
    const result = verifyPdf(buf, parsedData);

    return res.status(result.valid ? 200 : 422).json(result);
  } catch (err) {
    console.error("Unexpected error:", err);
    res.status(500).json({ error: "خطأ داخلي في الخادم", detail: err.message });
  }
});

// Health check
app.get("/health", (_req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ PDF Verifier running on port ${PORT}`);
});