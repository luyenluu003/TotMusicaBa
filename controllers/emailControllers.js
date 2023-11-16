const nodemailer = require("nodemailer");
const crypto = require("crypto");
const User = require("../models/user");

const verificationCodes = {};

const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: "violetbaka03@gmail.com",
    pass: "jmbyxxgecrertzod",
  },
});

const sendVerificationCode = (email) => {
  const verificationCode = crypto.randomInt(100000, 999999);
  verificationCodes[email] = verificationCode;

  const mailOptions = {
    from: "violetbaka03@gmail.com",
    to: email,
    subject: "Xác nhận code của Totmusica : ",
    text: `Mã xác nhận của bạn là: ${verificationCode}`,
  };

  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        reject("Lỗi khi gửi email xác nhận.");
      } else {
        console.log("Email xác nhận đã được gửi: " + info.response);
        resolve("Email xác nhận đã được gửi.");
      }
    });
  });
};

const verifyCode = (email, code) => {
  if (verificationCodes[email] && verificationCodes[email] == code) {
    delete verificationCodes[email];
    return "Xác nhận thành công.";
  } else {
    return "Mã xác nhận không đúng.";
  }
};

const checkEmailExistence = async (email) => {
  try {
    if (typeof email !== "string") {
      throw new Error("Invalid email format");
    }
    const existingUser = await User.findOne({ email });
    return !!existingUser;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

module.exports = { sendVerificationCode, verifyCode, checkEmailExistence };
