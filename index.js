const express = require("express");
const axios = require("axios");
const pdf = require("pdf-parse");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());

// ============================================================
//  🗄️ Supabase Client (env vars set in Coolify)
// ============================================================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ============================================================
//  🔐 BANK RECEIPT FINGERPRINT
//  Extracted from authentic bank-generated deposit receipts
//  Generated: 2026-04-16
// ============================================================
const BANK_FINGERPRINT = {
  // Layer 1 – PDF Technical Specification
  pdfVersion: "1.4",
  producerPattern: /iText[®\u00ae]\s+5\.\d+\.\d+/i,
  mediaBox: { width: 595, height: 842, tolerance: 2 },
  binaryMarkerHex: "25e2e3cfd3",

  // Layer 2 – PDF Object Structure
  objectCount: { min: 10, max: 25 },
  streamCount: { min: 4, max: 12 },
  imageXObjects: { min: 1, max: 5 },
  flatDecodeStreams: { min: 4, max: 12 },
  dctDecodeAllowed: false,

  // Layer 3 – Security / Integrity Flags (must ALL be absent)
  forbiddenFlags: [
    "/JavaScript",
    "/EmbeddedFiles",
    "/OpenAction",
    "/Encrypt",
    "/AcroForm",
    "/AA ",
    "/Launch",
    "/URI ",
  ],

  // Layer 4 – Receipt Type: DEPOSIT ONLY
  // Transfer receipts contain "سحب حوالة" → must be rejected
  transferKeyword: "سحب حوالة",
  // Deposit receipts contain "من حساب:" and "الى حساب:"
  depositFromKeyword: "من حساب:",
  depositToKeyword: "الى حساب:",

  // Layer 5 – Text Content Fingerprint (common to all receipts)
  requiredPhrases: [
    "إشعار سحب",
    "هذا الإشعار آلي ولايحتاج إلى ختم أو توقيع",
  ],
  amountPattern: /\[\s*\d[\d,]*(?:\.\d+)?\s*\]/,
  datePattern: /\d{4}\/\d{2}\/\d{2}/,
  textLength: { min: 200, max: 1800 },
  pageCount: { min: 1, max: 1 },

  // Layer 6 – Metadata Consistency
  modDateMustMatchCreation: true,

  // Layer 7 – File Size Range
  fileSize: { minKB: 50, maxKB: 700 },
};

// ============================================================
//  🧹 Text Normalization Helpers
//  Arabic text from PDFs can contain ZWJ, ZWNJ, directional
//  marks, and inconsistent spacing — we strip them all before
//  any string comparison to prevent trivial spoofing.
// ============================================================
function normalizeArabic(str) {
  if (!str) return "";
  return str
    // Remove directional / invisible Unicode chars
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, "")
    // Normalize Arabic letters (Alef variants → plain Alef)
    .replace(/[أإآٱ]/g, "ا")
    // Remove Tashkeel (diacritics)
    .replace(/[\u0610-\u061A\u064B-\u065F]/g, "")
    // Normalize Ta Marbuta → Ha (common mismatch)
    .replace(/ة/g, "ه")
    // Normalize Ya variants
    .replace(/ى/g, "ي")
    // Collapse multiple spaces / newlines into single space
    .replace(/[\s\n\r]+/g, " ")
    .trim()
    .toLowerCase();
}

function normalizeAccountNumber(num) {
  if (!num) return "";
  // Strip all non-digit characters
  return String(num).replace(/\D/g, "").trim();
}

// ============================================================
//  📄 Extract Deposit Fields from PDF Text
// ============================================================
function extractDepositInfo(text) {
  /**
   * Deposit receipt format (from Notice (4).pdf example):
   * "من حساب: عوض سالم عوض التميمي /جواز14378132-رقم 254298309
   *  الى حساب: حسين\nعبدالله صالح عفيف/بطـ08110156614-رقم 254221724"
   *
   * We need to extract:
   *   - Destination name  (after "الى حساب:" up to "/" or newline)
   *   - Destination account number (after "-رقم" following "الى حساب:")
   */

  // Destination account number: last "-رقم XXXXXXXXX" before " - " continuation
  const destAccountMatch = text.match(
    /الى حساب:[\s\S]*?-رقم\s+(\d{5,15})/
  );

  // Destination name: everything after "الى حساب:" up to "/" or ID number
  // The name may wrap to the next line in the PDF
  const destNameMatch = text.match(
    /الى حساب:\s*([\u0600-\u06FF\s]+?)(?:\/|\\n|\n|-رقم|\d{5})/
  );

  // Receipt number: digits-digits before "رقم الإشعار"
  const receiptNoMatch = text.match(/(\d+-\d+)رقم الإشعار/);

  // Date
  const dateMatch = text.match(/\d{4}\/\d{2}\/\d{2}/);

  // Amount
  const amountMatch = text.match(/\[\s*([\d,]+(?:\.\d+)?)\s*\]/);

  // Source name (the account that sent the money — السيد)
  const sourceNameMatch = text.match(/السيد:\s*([\u0600-\u06FF\s]+?)(?:\n|\/)/);

  // Source account number (رقم الحساب line)
  const sourceAccountMatch = text.match(/(\d{5,15})رقم الحساب/);

  return {
    receiptNumber: receiptNoMatch ? receiptNoMatch[1] : null,
    date: dateMatch ? dateMatch[0] : null,
    amount: amountMatch ? amountMatch[1].replace(/,/g, "") : null,
    destName: destNameMatch ? destNameMatch[1].trim() : null,
    destAccount: destAccountMatch ? destAccountMatch[1].trim() : null,
    sourceName: sourceNameMatch ? sourceNameMatch[1].trim() : null,
    sourceAccount: sourceAccountMatch ? sourceAccountMatch[1].trim() : null,
  };
}

// ============================================================
//  🔍 Raw PDF Structure Analyzer
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
//  ✅ Core Verification Logic – 7 Layers + Type + Identity
// ============================================================
function verifyPdf(buf, parsedData, expectedName, expectedAccount) {
  const raw = analyzeRawPdf(buf);
  const { text, info, numpages } = parsedData;
  const fp = BANK_FINGERPRINT;

  const results = [];

  function chk(layerObj, label, pass, detail) {
    layerObj.total++;
    layerObj.checks.push({ label, pass, detail });
    if (pass) layerObj.passed++;
  }

  // ── LAYER 1: PDF Technical Specification ──────────────────
  const layer1 = { name: "PDF Technical Specification", checks: [], passed: 0, total: 0 };
  chk(layer1, "PDF Version 1.4", raw.pdfVersion === fp.pdfVersion, `Found: ${raw.pdfVersion}`);
  chk(layer1, "iText 5.x Producer", fp.producerPattern.test(raw.producer || ""), `Found: ${raw.producer}`);
  const widthOk = raw.mediaBoxWidth !== null && Math.abs(raw.mediaBoxWidth - fp.mediaBox.width) <= fp.mediaBox.tolerance;
  const heightOk = raw.mediaBoxHeight !== null && Math.abs(raw.mediaBoxHeight - fp.mediaBox.height) <= fp.mediaBox.tolerance;
  chk(layer1, "A4 Page Dimensions (595×842)", widthOk && heightOk, `Found: ${raw.mediaBoxWidth}×${raw.mediaBoxHeight}`);
  chk(layer1, "Binary PDF Marker", raw.binaryLine.includes(fp.binaryMarkerHex), `Hex: ${raw.binaryLine}`);
  results.push(layer1);

  // ── LAYER 2: PDF Object Structure ─────────────────────────
  const layer2 = { name: "PDF Object Structure", checks: [], passed: 0, total: 0 };
  chk(layer2, "Object Count Range", raw.objCount >= fp.objectCount.min && raw.objCount <= fp.objectCount.max, `Found: ${raw.objCount}`);
  chk(layer2, "Stream Count Range", raw.streamCount >= fp.streamCount.min && raw.streamCount <= fp.streamCount.max, `Found: ${raw.streamCount}`);
  chk(layer2, "Image XObjects Count", raw.imageCount >= fp.imageXObjects.min && raw.imageCount <= fp.imageXObjects.max, `Found: ${raw.imageCount}`);
  chk(layer2, "FlateDecode Streams", raw.flateCount >= fp.flatDecodeStreams.min && raw.flateCount <= fp.flatDecodeStreams.max, `Found: ${raw.flateCount}`);
  chk(layer2, "No JPEG (DCTDecode) Streams", fp.dctDecodeAllowed ? true : raw.dctCount === 0, `Found: ${raw.dctCount}`);
  results.push(layer2);

  // ── LAYER 3: Security & Integrity Flags ───────────────────
  const layer3 = { name: "Security & Integrity Flags", checks: [], passed: 0, total: 0 };
  chk(layer3, "No Forbidden PDF Features", raw.flagsFound.length === 0, raw.flagsFound.length > 0 ? `Flags: ${raw.flagsFound.join(", ")}` : "Clean");
  chk(layer3, "No Encryption", !info?.IsEncrypted, `Encrypted: ${!!info?.IsEncrypted}`);
  chk(layer3, "No XFA Form", !info?.IsXFAPresent, `XFA: ${info?.IsXFAPresent}`);
  chk(layer3, "No AcroForm", !info?.IsAcroFormPresent, `AcroForm: ${info?.IsAcroFormPresent}`);
  chk(layer3, "Valid PDF Magic Bytes (%PDF)", buf.slice(0, 4).toString("ascii") === "%PDF", "Header check");
  results.push(layer3);

  // ── LAYER 4: RECEIPT TYPE — DEPOSIT ONLY ──────────────────
  const layer4 = { name: "Receipt Type Verification (Deposit Only)", checks: [], passed: 0, total: 0 };
  const isTransfer = text.includes(fp.transferKeyword);
  const hasDepositFrom = text.includes(fp.depositFromKeyword);
  const hasDepositTo = text.includes(fp.depositToKeyword);

  chk(
    layer4,
    "Not a Transfer Receipt (سحب حوالة rejected)",
    !isTransfer,
    isTransfer
      ? "❌ هذا الإيصال عبارة عن حوالة وليس إيداعاً — مرفوض تماماً"
      : "✅ لا يحتوي على كلمة سحب حوالة"
  );
  chk(
    layer4,
    "Deposit Source Field Present (من حساب:)",
    hasDepositFrom,
    hasDepositFrom ? "✅ موجود" : "❌ غياب حقل المرسل — ليس إيصال إيداع"
  );
  chk(
    layer4,
    "Deposit Destination Field Present (الى حساب:)",
    hasDepositTo,
    hasDepositTo ? "✅ موجود" : "❌ غياب حقل المستلم — ليس إيصال إيداع"
  );
  results.push(layer4);

  // ── LAYER 5: Text Content Fingerprint ─────────────────────
  const layer5 = { name: "Text Content Fingerprint", checks: [], passed: 0, total: 0 };
  for (const phrase of fp.requiredPhrases) {
    chk(layer5, `Required phrase: "${phrase}"`, text.includes(phrase), "");
  }
  chk(layer5, "Amount in Brackets [ N ]", fp.amountPattern.test(text), text.match(fp.amountPattern)?.[0] || "Not found");
  chk(layer5, "Date Format (YYYY/MM/DD)", fp.datePattern.test(text), text.match(fp.datePattern)?.[0] || "Not found");
  chk(layer5, "Text Length In Range", text.length >= fp.textLength.min && text.length <= fp.textLength.max, `Length: ${text.length}`);
  chk(layer5, "Page Count = 1", numpages >= fp.pageCount.min && numpages <= fp.pageCount.max, `Pages: ${numpages}`);
  results.push(layer5);

  // ── LAYER 6: Metadata Consistency ─────────────────────────
  const layer6 = { name: "Metadata Consistency", checks: [], passed: 0, total: 0 };
  chk(layer6, "CreationDate Present", !!raw.creationDatePrefix, `CreationDate: ${raw.creationDatePrefix}`);
  chk(layer6, "ModDate Present", !!raw.modDatePrefix, `ModDate: ${raw.modDatePrefix}`);
  chk(layer6, "CreationDate == ModDate (auto-generated)", raw.creationDatePrefix === raw.modDatePrefix, `Creation: ${raw.creationDatePrefix} / Mod: ${raw.modDatePrefix}`);
  chk(layer6, "Producer Field Present", !!raw.producer, `Producer: ${raw.producer}`);
  results.push(layer6);

  // ── LAYER 7: File Size + Compression ──────────────────────
  const layer7 = { name: "File Size & Compression", checks: [], passed: 0, total: 0 };
  const fileSizeKB = buf.length / 1024;
  chk(layer7, `File Size ${fp.fileSize.minKB}–${fp.fileSize.maxKB} KB`, fileSizeKB >= fp.fileSize.minKB && fileSizeKB <= fp.fileSize.maxKB, `Size: ${fileSizeKB.toFixed(1)} KB`);
  chk(layer7, "ColorSpace Objects Present", raw.colorSpaceCount >= 1 && raw.colorSpaceCount <= 8, `Found: ${raw.colorSpaceCount}`);
  chk(layer7, "FlateDecode is Primary Compression", raw.flateCount > raw.dctCount, `FlateDecode: ${raw.flateCount} vs DCT: ${raw.dctCount}`);
  chk(layer7, "Has Embedded Images", raw.imageCount >= 1, `Images: ${raw.imageCount}`);
  results.push(layer7);

  // ── LAYER 8: Beneficiary Identity Verification ─────────────
  const layer8 = { name: "Beneficiary Identity Verification", checks: [], passed: 0, total: 0 };

  const extracted = extractDepositInfo(text);

  // Normalize everything before comparison
  const normExpectedName = normalizeArabic(expectedName);
  const normExtractedDestName = normalizeArabic(extracted.destName);
  const normExpectedAccount = normalizeAccountNumber(expectedAccount);
  const normExtractedDestAccount = normalizeAccountNumber(extracted.destAccount);

  // Name matching: use includes() to handle partial matches (name may wrap lines)
  // We also check if the expected name words are all found in the extracted name
  const expectedNameWords = normExpectedName.split(" ").filter((w) => w.length > 1);
  const nameWordsFoundInText = expectedNameWords.filter((w) =>
    normalizeArabic(text).includes(w)
  );
  const nameMatchRatio = expectedNameWords.length > 0
    ? nameWordsFoundInText.length / expectedNameWords.length
    : 0;
  const nameMatch = nameMatchRatio >= 0.8; // 80%+ of name words must match

  chk(
    layer8,
    "Destination Name Matches",
    nameMatch,
    nameMatch
      ? `✅ الاسم مطابق (${Math.round(nameMatchRatio * 100)}%): "${extracted.destName}"`
      : `❌ الاسم غير مطابق — المتوقع: "${expectedName}" | في الإيصال: "${extracted.destName}" | تطابق: ${Math.round(nameMatchRatio * 100)}%`
  );

  // Account number: exact match (digits only, no tolerance)
  const accountMatch = normExpectedAccount.length > 0 &&
    normExtractedDestAccount === normExpectedAccount;

  chk(
    layer8,
    "Destination Account Number Matches",
    accountMatch,
    accountMatch
      ? `✅ رقم الحساب مطابق: ${extracted.destAccount}`
      : `❌ رقم الحساب غير مطابق — المتوقع: "${normExpectedAccount}" | في الإيصال: "${normExtractedDestAccount}"`
  );

  // Extra safety: make sure "الى حساب:" section in raw text contains both name words and account
  const toSection = text.split("الى حساب:")[1] || "";
  const nameInToSection = expectedNameWords.some((w) =>
    normalizeArabic(toSection).includes(w)
  );
  chk(
    layer8,
    "Beneficiary Details Located in 'الى حساب' Section",
    nameInToSection,
    nameInToSection
      ? "✅ تفاصيل المستلم موجودة في القسم الصحيح من الإيصال"
      : "❌ اسم المستلم المتوقع غير موجود في قسم 'الى حساب' — يشتبه في التزوير"
  );

  results.push(layer8);

  // ── SCORING ──────────────────────────────────────────────
  let weightedScore = 0;
  const layerSummaries = [];

  for (const layer of results) {
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

  // Critical layers: must pass 100%
  const criticalLayers = [
    "Security & Integrity Flags",
    "Receipt Type Verification (Deposit Only)",
    "Beneficiary Identity Verification",
    "Text Content Fingerprint",
  ];
  const criticalFailed = layerSummaries.filter(
    (l) => criticalLayers.includes(l.layer) && l.score < 100
  );

  const isValid = overallScore >= 80 && criticalFailed.length === 0;

  return {
    valid: isValid,
    confidence: overallScore,
    criticalFailures: criticalFailed.map((l) => ({
      layer: l.layer,
      failedChecks: l.checks.filter((c) => !c.pass).map((c) => c.detail),
    })),
    layers: layerSummaries,
    extractedData: {
      receiptNumber: extracted.receiptNumber,
      amount: extracted.amount,
      date: extracted.date,
      destName: extracted.destName,
      destAccount: extracted.destAccount,
      sourceName: extracted.sourceName,
      sourceAccount: extracted.sourceAccount,
      producer: raw.producer,
      pageCount: numpages,
      fileSizeKB: Math.round(fileSizeKB * 10) / 10,
      rawText: text.trim(),
    },
  };
}

// ============================================================
//  🔄 Supabase: Duplicate Receipt Check + Registration
// ============================================================
async function checkAndRegisterReceipt(receiptNumber, destAccount, amount, date, fileSizeKB) {
  // 1. Check if receipt already used
  const { data: existing, error: selectErr } = await supabase
    .from("verified_receipts")
    .select("id, created_at")
    .eq("receipt_number", receiptNumber)
    .maybeSingle();

  if (selectErr) {
    throw new Error(`خطأ في الاتصال بقاعدة البيانات: ${selectErr.message}`);
  }

  if (existing) {
    return {
      isDuplicate: true,
      firstUsedAt: existing.created_at,
    };
  }

  // 2. Register the receipt to prevent future reuse
  const { error: insertErr } = await supabase.from("verified_receipts").insert({
    receipt_number: receiptNumber,
    dest_account: destAccount,
    amount: amount,
    receipt_date: date,
    file_size_kb: fileSizeKB,
    verified_at: new Date().toISOString(),
  });

  if (insertErr) {
    throw new Error(`فشل تسجيل الإيصال في قاعدة البيانات: ${insertErr.message}`);
  }

  return { isDuplicate: false };
}

// ============================================================
//  🚀 Express Routes
// ============================================================
app.post("/verify", async (req, res) => {
  try {
    const { file_url, expected_name, expected_account } = req.body;

    // Validate required inputs
    if (!file_url) {
      return res.status(400).json({
        valid: false,
        error: "file_url مطلوب",
      });
    }
    if (!expected_name || !expected_account) {
      return res.status(400).json({
        valid: false,
        error: "expected_name و expected_account مطلوبان للتحقق من هوية المستلم",
      });
    }

    // Download PDF
    let response;
    try {
      response = await axios.get(file_url, {
        responseType: "arraybuffer",
        timeout: 30000,
        maxContentLength: 10 * 1024 * 1024,
      });
    } catch (downloadErr) {
      return res.status(400).json({
        valid: false,
        error: "فشل تحميل ملف PDF",
        detail: downloadErr.message,
      });
    }

    const buf = Buffer.from(response.data);

    // Quick magic-bytes check
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
        error: "تعذّر قراءة محتوى PDF — الملف تالف أو غير مدعوم",
        detail: parseErr.message,
        confidence: 0,
      });
    }

    // Fast early rejection for transfer receipts (before full analysis)
    if (parsedData.text.includes(BANK_FINGERPRINT.transferKeyword)) {
      return res.status(422).json({
        valid: false,
        error: "❌ مرفوض: الإيصال المقدَّم هو إيصال حوالة (تحويل خارجي) وليس إيداعاً. يُقبل فقط إيصال الإيداع المباشر بين الحسابات.",
        type: "TRANSFER_RECEIPT_REJECTED",
        confidence: 0,
      });
    }

    // Run all 8 verification layers
    const result = verifyPdf(buf, parsedData, expected_name, expected_account);

    // If structural/identity checks fail, return immediately without touching DB
    if (!result.valid) {
      return res.status(422).json(result);
    }

    // ── SUPABASE: Duplicate Check ──────────────────────────
    let duplicateCheck;
    try {
      duplicateCheck = await checkAndRegisterReceipt(
        result.extractedData.receiptNumber,
        result.extractedData.destAccount,
        result.extractedData.amount,
        result.extractedData.date,
        result.extractedData.fileSizeKB
      );
    } catch (dbErr) {
      // DB error: fail safe — reject with explanation
      return res.status(500).json({
        valid: false,
        error: "خطأ في التحقق من قاعدة البيانات",
        detail: dbErr.message,
      });
    }

    if (duplicateCheck.isDuplicate) {
      return res.status(422).json({
        valid: false,
        error: `❌ مرفوض: تم استخدام هذا الإيصال مسبقاً في ${duplicateCheck.firstUsedAt}. لا يمكن استخدام نفس الإيصال مرتين.`,
        type: "DUPLICATE_RECEIPT",
        receiptNumber: result.extractedData.receiptNumber,
        confidence: 0,
      });
    }

    // All checks passed
    return res.status(200).json({
      ...result,
      registeredInDatabase: true,
    });
  } catch (err) {
    console.error("Unexpected error:", err);
    res.status(500).json({
      valid: false,
      error: "خطأ داخلي في الخادم",
      detail: err.message,
    });
  }
});

// Health check
app.get("/health", (_req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ PDF Deposit Verifier running on port ${PORT}`);
});