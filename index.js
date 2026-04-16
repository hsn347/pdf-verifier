const express = require("express");
const axios = require("axios");
const pdf = require("pdf-parse");

const app = express();
app.use(express.json());

app.post("/verify", async (req, res) => {
    try {
        const { file_url } = req.body;

        if (!file_url) {
            return res.status(400).json({ error: "file_url مطلوب" });
        }

        // تحميل PDF
        const response = await axios.get(file_url, {
            responseType: "arraybuffer"
        });

        const data = await pdf(response.data);
        const text = data.text;

        let score = 0;

        // تحقق النص
        if (text.includes("إشعار سحب")) score += 20;
        if (text.includes("هذا الإشعار آلي")) score += 20;

        // رقم مرجع
        const ref = text.match(/Omq[A-Za-z0-9]+/);
        if (ref) score += 20;

        // بنية
        if (text.includes("[") && text.includes("]")) score += 20;

        // طول النص
        if (text.length > 200) score += 20;

        const isValid = score >= 80;

        res.json({
            valid: isValid,
            confidence: score,
            data: {
                reference: ref?.[0] || null
            }
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});