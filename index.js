const express = require("express");
const axios = require("axios");
const pdf = require("pdf-parse");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());

// ============================================================
//  🗄️ Supabase Client (env vars set in Coolify)
// ============================================================
let supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY) {
    supabase = createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_KEY
    );
}

// ============================================================
//  🔐 BANK RECEIPT FINGERPRINT
//  Extracted from authentic bank-generated deposit receipts
// ============================================================
const BANK_FINGERPRINT = {
    pdfVersion: "1.4",
    producerPattern: /iText[®\u00ae]\s+5\.\d+\.\d+/i,
    mediaBox: { width: 595, height: 842, tolerance: 2 },
    binaryMarkerHex: "25e2e3cfd3",
    objectCount: { min: 10, max: 25 },
    streamCount: { min: 4, max: 12 },
    imageXObjects: { min: 1, max: 5 },
    flatDecodeStreams: { min: 4, max: 12 },
    dctDecodeAllowed: false,
    forbiddenFlags: [
        "/JavaScript", "/EmbeddedFiles", "/OpenAction", "/Encrypt",
        "/AcroForm", "/AA ", "/Launch", "/URI ",
    ],
    transferKeyword: "سحب حوالة",
    depositFromKeyword: "من حساب:",
    depositToKeyword: "الى حساب:",
    requiredPhrases: [
        "إشعار سحب",
        "هذا الإشعار آلي ولايحتاج إلى ختم أو توقيع",
    ],
    amountPattern: /\[\s*\d[\d,]*(?:\.\d+)?\s*\]/,
    datePattern: /\d{4}\/\d{2}\/\d{2}/,
    textLength: { min: 200, max: 1800 },
    pageCount: { min: 1, max: 1 },
    modDateMustMatchCreation: true,
    fileSize: { minKB: 50, maxKB: 700 },
};

// ============================================================
//  🌍 Known Currency Aliases (for smart normalization)
// ============================================================
const CURRENCY_ALIASES = {
    "ريال يمني": ["يمني", "yer", "yemeni", "yemeni rial"],
    "ريال سعودي": ["سعودي", "sar", "saudi", "riyal"],
    "دولار": ["dollar", "usd", "دولار امريكي", "امريكي"],
    "يورو": ["euro", "eur"],
    "دينار": ["dinar", "kwd", "iqd", "jod"],
    "درهم": ["dirham", "aed", "اماراتي"],
    "جنيه": ["pound", "egp", "جنيه مصري"],
};

// ============================================================
//  🧹 Normalization Helpers
// ============================================================
function normalizeArabic(str) {
    if (!str) return "";
    return str
        .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, "")
        .replace(/[أإآٱ]/g, "ا")
        .replace(/[\u0610-\u061A\u064B-\u065F]/g, "")
        .replace(/ة/g, "ه")
        .replace(/ى/g, "ي")
        .replace(/[\s\n\r]+/g, " ")
        .trim()
        .toLowerCase();
}

function normalizeAccountNumber(num) {
    return String(num || "").replace(/\D/g, "").trim();
}

function normalizeCurrency(cur) {
    if (!cur) return "";
    // Normalize Arabic, then strip non-letter chars
    const norm = normalizeArabic(cur);
    // Also lowercase for Latin characters
    return norm.replace(/\s+/g, " ").trim();
}

/**
 * Smart currency matching:
 * Checks canonical name, all aliases, and substring containment.
 * Returns { match: bool, normalizedExpected, normalizedExtracted, canonicalMatch }
 */
function matchCurrency(expected, extracted) {
    const normExp = normalizeCurrency(expected);
    const normExt = normalizeCurrency(extracted);

    // 1. Direct match
    if (normExp === normExt) return { match: true, method: "direct" };

    // 2. One contains the other (handles "يمني" vs "ريال يمني")
    if (normExt.includes(normExp) || normExp.includes(normExt)) {
        return { match: true, method: "contains" };
    }

    // 3. Check alias map for both sides
    for (const [canonical, aliases] of Object.entries(CURRENCY_ALIASES)) {
        const normCanonical = normalizeCurrency(canonical);
        const allForms = [normCanonical, ...aliases.map(normalizeCurrency)];

        const expIsThis = allForms.some((f) => normExp === f || normExp.includes(f) || f.includes(normExp));
        const extIsThis = allForms.some((f) => normExt === f || normExt.includes(f) || f.includes(normExt));

        if (expIsThis && extIsThis) {
            return { match: true, method: "alias", canonical };
        }
    }

    return { match: false, method: "none" };
}

// ============================================================
//  📄 Deposit Info Extractor
// ============================================================
function extractDepositInfo(text) {
    // ── Destination (Beneficiary) ──────────────────────────────
    const toSectionRaw = text.split("الى حساب:")[1] || "";

    /**
     * FIX: The name wraps across lines in PDF text.
     * Old (BROKEN) regex stopped at first \n → captured only "حسين"
     * New approach: split at "/" which precedes the ID type (بطـ / جواز)
     * "حسين\nعبدالله صالح عفيف/بطـ08110156614" → before "/" → full name
     */
    const nameBeforeSlash = (toSectionRaw.split("/")[0] || "").trim();
    const destNameFull = nameBeforeSlash.replace(/[\n\r\s]+/g, " ").trim();

    // Destination account: "-رقم XXXXXXXXX" in الى حساب section
    const destAccountMatch = toSectionRaw.match(/-رقم\s+(\d{5,15})/);

    // ── Source ────────────────────────────────────────────────
    const sourceNameMatch = text.match(/السيد:\s*([\u0600-\u06FF\s]+?)(?:\n|\/)/);
    const sourceAccountMatch = text.match(/(\d{5,15})رقم الحساب/);

    // ── Common Fields ─────────────────────────────────────────
    const receiptNoMatch = text.match(/(\d+-\d+)رقم الإشعار/);
    const dateMatch = text.match(/\d{4}\/\d{2}\/\d{2}/);
    const amountMatch = text.match(/\[\s*([\d,]+(?:\.\d+)?)\s*\]/);

    return {
        receiptNumber: receiptNoMatch ? receiptNoMatch[1] : null,
        date: dateMatch ? dateMatch[0] : null,
        amount: amountMatch ? amountMatch[1].replace(/,/g, "") : null,
        destName: destNameFull || null,
        destAccount: destAccountMatch ? destAccountMatch[1].trim() : null,
        sourceName: sourceNameMatch ? sourceNameMatch[1].trim() : null,
        sourceAccount: sourceAccountMatch ? sourceAccountMatch[1].trim() : null,
    };
}

// ============================================================
//  💱 Smart Currency Extractor
// ============================================================
function extractCurrency(text) {
    /**
     * PDF currency format (confirmed from real receipts):
     *   "ريال يمني[ 3000 ]المبلغ"  → currency on same line before bracket
     *   "سعودي[ 370 ]المبلغ"        → sometimes only last word appears
     *
     * Strategy: capture everything on the line that ends with "[amount]"
     * Pattern: start of line (after \n) → Arabic words → [ digits ]
     */
    const currencyLineMatch = text.match(/\n([\u0600-\u06FF][^\n]*?)\[\s*[\d,]+\s*\]/);
    if (currencyLineMatch) {
        const lineContent = currencyLineMatch[1].trim();
        // If the whole line is just currency words (no other content), return it
        if (/^[\u0600-\u06FF\s]+$/.test(lineContent)) {
            return lineContent.replace(/\s+/g, " ").trim();
        }
        // Otherwise take the last 1–3 Arabic words on that line
        const words = lineContent.split(/\s+/).filter((w) => /[\u0600-\u06FF]/.test(w));
        if (words.length >= 2) return words.slice(-2).join(" ");
        if (words.length === 1) return words[0];
    }

    // Fallback: check amount-in-words line (after ]المبلغ)
    // Example: "] المبلغ\nثلاثة آلاف ريال يمني"
    const amountWordsMatch = text.match(/\]\s*المبلغ\s*\n([\u0600-\u06FF\s]+)/);
    if (amountWordsMatch) {
        const quantityWords = new Set([
            "الف", "ألف", "آلاف", "مائة", "مليون", "مليار",
            "واحد", "اثنان", "ثلاثة", "اربعة", "أربعة", "خمسة", "ستة",
            "سبعة", "ثمانية", "تسعة", "عشرة", "عشرون", "ثلاثون",
            "و", "فقط", "من",
        ]);
        const words = amountWordsMatch[1].trim().split(/\s+/).filter(Boolean);
        const currencyWords = [];
        for (let i = words.length - 1; i >= 0; i--) {
            if (quantityWords.has(normalizeArabic(words[i]))) continue;
            currencyWords.unshift(words[i]);
            // Check if previous word is part of currency (e.g., "ريال" before "يمني")
            if (i > 0 && !quantityWords.has(normalizeArabic(words[i - 1]))) {
                const prevIsUnit = ["ريال", "دينار", "درهم", "دولار", "يورو", "جنيه"].some(
                    (u) => normalizeArabic(words[i - 1]).includes(u)
                );
                if (prevIsUnit) currencyWords.unshift(words[i - 1]);
            }
            break;
        }
        if (currencyWords.length > 0) return currencyWords.join(" ");
    }

    return null;
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
    const flagsFound = BANK_FINGERPRINT.forbiddenFlags.filter((f) => raw.includes(f));

    let mediaBoxWidth = null, mediaBoxHeight = null;
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
        mediaBoxWidth, mediaBoxHeight, binaryLine,
        objCount, streamCount, imageCount, flateCount, dctCount, colorSpaceCount,
        flagsFound,
        creationDatePrefix: creationMatch ? creationMatch[1] : null,
        modDatePrefix: modMatch ? modMatch[1] : null,
    };
}

// ============================================================
//  ✅ Core Verification Logic – 9 Layers
// ============================================================
function verifyPdf(buf, parsedData, expectedName, expectedAccount, expectedCurrency) {
    const raw = analyzeRawPdf(buf);
    const { text, info, numpages } = parsedData;
    const fp = BANK_FINGERPRINT;
    const results = [];

    function chk(layerObj, label, pass, detail) {
        layerObj.total = (layerObj.total || 0) + 1;
        layerObj.checks = layerObj.checks || [];
        layerObj.passed = (layerObj.passed || 0) + (pass ? 1 : 0);
        layerObj.checks.push({ label, pass, detail });
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
    chk(layer2, "No JPEG (DCTDecode) Streams", raw.dctCount === 0, `Found: ${raw.dctCount}`);
    results.push(layer2);

    // ── LAYER 3: Security & Integrity Flags ───────────────────
    const layer3 = { name: "Security & Integrity Flags", checks: [], passed: 0, total: 0 };
    chk(layer3, "No Forbidden PDF Features", raw.flagsFound.length === 0, raw.flagsFound.length ? `Flags: ${raw.flagsFound.join(", ")}` : "Clean");
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
    chk(layer4, "Not a Transfer Receipt", !isTransfer,
        isTransfer ? "❌ هذا إيصال حوالة — مرفوض. يُقبل فقط إيصال الإيداع المباشر" : "✅ ليس حوالة");
    chk(layer4, "Deposit Source Field (من حساب:)", hasDepositFrom, hasDepositFrom ? "✅ موجود" : "❌ غائب");
    chk(layer4, "Deposit Destination Field (الى حساب:)", hasDepositTo, hasDepositTo ? "✅ موجود" : "❌ غائب");
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
    chk(layer6, "CreationDate == ModDate (auto-generated)", raw.creationDatePrefix === raw.modDatePrefix,
        `Creation: ${raw.creationDatePrefix} / Mod: ${raw.modDatePrefix}`);
    chk(layer6, "Producer Field Present", !!raw.producer, `Producer: ${raw.producer}`);
    results.push(layer6);

    // ── LAYER 7: File Size & Compression ──────────────────────
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

    // Name matching (normalized, word-by-word, searches full text for flexibility)
    const normExpectedName = normalizeArabic(expectedName);
    const expectedNameWords = normExpectedName.split(" ").filter((w) => w.length > 1);
    const nameWordsInText = expectedNameWords.filter((w) => normalizeArabic(text).includes(w));
    const nameWordsInToSection = expectedNameWords.filter((w) =>
        normalizeArabic(text.split("الى حساب:")[1] || "").includes(w)
    );
    const nameRatioText = expectedNameWords.length ? nameWordsInText.length / expectedNameWords.length : 0;
    const nameRatioSection = expectedNameWords.length ? nameWordsInToSection.length / expectedNameWords.length : 0;
    const nameMatch = nameRatioText >= 0.8;

    chk(layer8, "Destination Name Matches (Full Text)",
        nameMatch,
        nameMatch
            ? `✅ تطابق ${Math.round(nameRatioText * 100)}% — الاسم المستخرج: "${extracted.destName}"`
            : `❌ تطابق ${Math.round(nameRatioText * 100)}% فقط — المتوقع: "${expectedName}" | المستخرج: "${extracted.destName}"`
    );

    chk(layer8, "Beneficiary Name Located in 'الى حساب' Section",
        nameRatioSection >= 0.8,
        nameRatioSection >= 0.8
            ? `✅ الاسم موجود في القسم الصحيح (${Math.round(nameRatioSection * 100)}%)`
            : `❌ الاسم غير موجود في قسم المستلم — احتمال تزوير (${Math.round(nameRatioSection * 100)}% فقط)`
    );

    // Account number: exact digits match
    const normExpectedAccount = normalizeAccountNumber(expectedAccount);
    const normExtractedAccount = normalizeAccountNumber(extracted.destAccount);
    const accountMatch = normExpectedAccount.length > 0 && normExtractedAccount === normExpectedAccount;
    chk(layer8, "Destination Account Number Matches",
        accountMatch,
        accountMatch
            ? `✅ رقم الحساب مطابق: ${extracted.destAccount}`
            : `❌ غير مطابق — المتوقع: "${normExpectedAccount}" | في الإيصال: "${normExtractedAccount}"`
    );

    // Extra: account number must be in الى حساب section (not only in sender's block)
    const toSectionText = text.split("الى حساب:")[1] || "";
    const accountInToSection = toSectionText.includes(normExpectedAccount);
    chk(layer8, "Account Number Located in 'الى حساب' Section",
        accountInToSection,
        accountInToSection
            ? "✅ رقم الحساب موجود في قسم المستلم"
            : "❌ رقم الحساب غير موجود في قسم 'الى حساب' — تحقق مشبوه"
    );

    results.push(layer8);

    // ── LAYER 9: Currency Verification ────────────────────────
    const layer9 = { name: "Currency Verification", checks: [], passed: 0, total: 0 };
    const extractedCurrency = extractCurrency(text);

    chk(layer9, "Currency Extracted Successfully",
        !!extractedCurrency,
        extractedCurrency ? `✅ العملة المستخرجة: "${extractedCurrency}"` : "❌ تعذّر استخراج العملة من الإيصال"
    );

    // Currency consistency: must appear in BOTH the amount line AND the amount-in-words line
    const amountLine = (text.match(/\n([^\n]*?)\[\s*[\d,]+\s*\]/)?.[1] || "").trim();
    const amountWordsLine = (text.match(/\]\s*المبلغ\s*\n([^\n]+)/)?.[1] || "").trim();
    const currencyConsistent = extractedCurrency &&
        (normalizeArabic(amountWordsLine).includes(normalizeArabic(extractedCurrency)) ||
            normalizeArabic(amountLine).includes(normalizeArabic(extractedCurrency)));
    chk(layer9, "Currency Consistent Within Receipt",
        currencyConsistent,
        currencyConsistent
            ? `✅ العملة متسقة: "${extractedCurrency}" في سطر المبلغ`
            : `❌ العملة غير متسقة أو مشبوهة`
    );

    if (expectedCurrency) {
        const currencyMatchResult = matchCurrency(expectedCurrency, extractedCurrency || "");
        chk(layer9, "Currency Matches Expected",
            currencyMatchResult.match,
            currencyMatchResult.match
                ? `✅ العملة مطابقة (${currencyMatchResult.method}): "${extractedCurrency}"`
                : `❌ العملة غير مطابقة — المتوقع: "${expectedCurrency}" | في الإيصال: "${extractedCurrency}"`
        );
    } else {
        // No expected currency provided — we just report what we found (informational)
        chk(layer9, "Expected Currency Provided",
            false,
            `⚠️ لم يتم تمرير expected_currency — العملة المستخرجة: "${extractedCurrency}" (يُنصح بإضافتها للأمان)`
        );
    }

    results.push(layer9);

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

    // Critical layers: must score 100%
    const criticalLayers = [
        "Security & Integrity Flags",
        "Receipt Type Verification (Deposit Only)",
        "Beneficiary Identity Verification",
        "Text Content Fingerprint",
    ];
    // Currency is critical ONLY if expected_currency was provided
    if (expectedCurrency) criticalLayers.push("Currency Verification");

    const criticalFailed = layerSummaries.filter(
        (l) => criticalLayers.includes(l.layer) && l.score < 100
    );

    const isValid = overallScore >= 80 && criticalFailed.length === 0;

    return {
        valid: isValid,
        confidence: overallScore,
        criticalFailures: criticalFailed.map((l) => ({
            layer: l.layer,
            failedChecks: l.checks.filter((c) => !c.pass).map((c) => ({ label: c.label, detail: c.detail })),
        })),
        layers: layerSummaries,
        extractedData: {
            receiptNumber: extracted.receiptNumber,
            amount: extracted.amount,
            currency: extractedCurrency,
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
//  🔄 Supabase: Duplicate Check + Registration
// ============================================================
async function checkAndRegisterReceipt(receiptNumber, destAccount, destName, amount, currency, date, fileSizeKB) {
    if (!supabase) {
        console.warn("⚠️ Supabase not configured — skipping duplicate check");
        return { isDuplicate: false, skipped: true };
    }

    const { data: existing, error: selectErr } = await supabase
        .from("verified_receipts")
        .select("id, verified_at")
        .eq("receipt_number", receiptNumber)
        .maybeSingle();

    if (selectErr) throw new Error(`خطأ في قاعدة البيانات: ${selectErr.message}`);

    if (existing) {
        return { isDuplicate: true, firstUsedAt: existing.verified_at };
    }

    const { error: insertErr } = await supabase.from("verified_receipts").insert({
        receipt_number: receiptNumber,
        dest_account: destAccount,
        dest_name: destName,        // اسم المودع (المستلم)
        amount,
        currency,
        receipt_date: date,
        file_size_kb: fileSizeKB,
        verified_at: new Date().toISOString(),
    });

    if (insertErr) throw new Error(`فشل حفظ الإيصال: ${insertErr.message}`);

    return { isDuplicate: false };
}

// ============================================================
//  📦 Response Builders
// ============================================================

/**
 * REJECTION — slim payload for n8n:
 *   only the reason + depositor name (if extracted)
 */
function rejectResponse(rejectionType, rejectionReason, depositorName = null) {
    return {
        valid: false,
        rejectionType,
        rejectionReason,
        depositorName,   // اسم المودع من الإيصال (إن أمكن استخراجه)
    };
}

/**
 * SUCCESS — full payload with all layers + extracted data
 */
function successResponse({ confidence, layers, extractedData, registeredInDatabase }) {
    return {
        valid: true,
        confidence,
        layers,
        extractedData,
        registeredInDatabase,
    };
}

// ============================================================
//  🚀 Express Routes
// ============================================================
app.post("/verify", async (req, res) => {
    try {
        const { file_url, expected_name, expected_account, expected_currency } = req.body;

        if (!file_url || !expected_name || !expected_account) {
            return res.status(400).json(rejectResponse(
                "MISSING_PARAMS",
                "الحقول المطلوبة: file_url, expected_name, expected_account — ملاحظة: expected_currency اختياري لكن يُوصى به"
            ));
        }

        // ── Download PDF ─────────────────────────────────────────
        let response;
        try {
            response = await axios.get(file_url, {
                responseType: "arraybuffer",
                timeout: 30000,
                maxContentLength: 10 * 1024 * 1024,
            });
        } catch (downloadErr) {
            return res.status(400).json(rejectResponse(
                "DOWNLOAD_ERROR",
                `فشل تحميل ملف PDF من الرابط المُقدَّم — ${downloadErr.message}`
            ));
        }

        const buf = Buffer.from(response.data);

        // ── PDF Magic Bytes ───────────────────────────────────────
        if (buf.slice(0, 4).toString("ascii") !== "%PDF") {
            return res.status(422).json(rejectResponse(
                "INVALID_PDF",
                "الملف المُرسَل ليس ملف PDF صحيحاً — تحقق من الرابط"
            ));
        }

        // ── Parse PDF Text ───────────────────────────────────────
        let parsedData;
        try {
            parsedData = await pdf(buf);
        } catch (parseErr) {
            return res.status(422).json(rejectResponse(
                "INVALID_PDF",
                `تعذّر قراءة محتوى PDF — الملف تالف أو مشفّر — ${parseErr.message}`
            ));
        }

        // ── Fast Rejection: Transfer Receipt ─────────────────────
        if (parsedData.text.includes(BANK_FINGERPRINT.transferKeyword)) {
            // Try to get sender name even from transfer receipt
            const senderMatch = parsedData.text.match(/السيد:\s*([\u0600-\u06FF\s]+?)(?:\n|\/)/);
            const senderName = senderMatch ? senderMatch[1].trim() : null;
            return res.status(422).json(rejectResponse(
                "TRANSFER_RECEIPT_REJECTED",
                "الإيصال المُقدَّم هو إيصال حوالة (تحويل خارجي) وليس إيداعاً. يُقبل فقط إيصال الإيداع المباشر بين الحسابات داخل نفس البنك.",
                senderName
            ));
        }

        // ── Run All 9 Verification Layers ────────────────────────
        const result = verifyPdf(buf, parsedData, expected_name, expected_account, expected_currency);

        if (!result.valid) {
            const reasons = result.criticalFailures
                .flatMap((cf) => cf.failedChecks.map((fc) => fc.detail))
                .filter(Boolean)
                .join(" | ");

            return res.status(422).json(rejectResponse(
                "VERIFICATION_FAILED",
                reasons || "فشل التحقق من الإيصال",
                result.extractedData?.destName || null
            ));
        }

        // ── Supabase: Duplicate Check + Register ─────────────────
        let duplicateCheck;
        try {
            duplicateCheck = await checkAndRegisterReceipt(
                result.extractedData.receiptNumber,
                result.extractedData.destAccount,
                result.extractedData.destName,      // اسم المودع
                result.extractedData.amount,
                result.extractedData.currency,
                result.extractedData.date,
                result.extractedData.fileSizeKB
            );
        } catch (dbErr) {
            return res.status(500).json(rejectResponse(
                "DATABASE_ERROR",
                `خطأ في قاعدة البيانات أثناء التحقق من الإيصال — ${dbErr.message}`,
                result.extractedData?.destName || null
            ));
        }

        if (duplicateCheck.isDuplicate) {
            return res.status(422).json(rejectResponse(
                "DUPLICATE_RECEIPT",
                `تم استخدام الإيصال رقم ${result.extractedData.receiptNumber} مسبقاً في ` +
                `${new Date(duplicateCheck.firstUsedAt).toLocaleString("ar-YE")}. ` +
                `لا يُسمح باستخدام نفس الإيصال مرتين.`,
                result.extractedData?.destName || null
            ));
        }

        // ── All Checks Passed — return full data ─────────────────
        return res.status(200).json(successResponse({
            confidence: result.confidence,
            layers: result.layers,
            extractedData: result.extractedData,
            registeredInDatabase: !duplicateCheck.skipped,
        }));

    } catch (err) {
        console.error("Unexpected error:", err);
        res.status(500).json(rejectResponse(
            "SERVER_ERROR",
            `خطأ داخلي في الخادم — ${err.message}`
        ));
    }
});

app.get("/health", (_req, res) => res.json({ status: "ok", supabase: !!supabase }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ PDF Deposit Verifier running on port ${PORT}`));