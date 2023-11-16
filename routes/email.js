const express = require("express");
const router = express.Router();
const {
  sendVerificationCode,
  verifyCode,
  checkEmailExistence,
} = require("../controllers/emailControllers");

router.post("/send-verification-code", async (req, res) => {
  const { email } = req.body;
  try {
    const response = await sendVerificationCode(email);
    res.status(200).send(response);
  } catch (error) {
    res.status(500).send(error);
  }
});

router.post("/verify-code", (req, res) => {
  const { email, code } = req.body;
  const response = verifyCode(email, code);
  res.status(response.startsWith("Xác nhận") ? 200 : 400).send(response);
});

//check email
router.post("/check-email", async (req, res) => {
  const { email } = req.body;
  try {
    const isEmailExist = await checkEmailExistence(email);
    res.status(200).json({ isEmailExist });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;
