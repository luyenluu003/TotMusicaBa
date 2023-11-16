const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/user");

let refreshTokens = [];

const authController = {
  //REGISTER
  regisrterUser: async (req, res) => {
    try {
      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(req.body.password, salt);

      //create new user
      const newUser = await new User({
        username: req.body.username,
        email: req.body.email,
        password: hashed,
      });

      //save to DB;
      const user = await newUser.save();
      res.status(200).json(user);
    } catch (err) {
      res.status(500).json(err);
    }
  },
  //GENERATE ACCESS TOKEN
  generateAccressToken: (user) => {
    return jwt.sign(
      {
        id: user.id,
        admin: user.admin,
      },
      process.env.JWT_ACCESS_KEY,
      { expiresIn: "30d" }
    );
  },

  //GENERATE REFRESH TOKEN
  generateRefreshToken: (user) => {
    return jwt.sign(
      {
        id: user.id,
        admin: user.admin,
      },
      process.env.JWT_REFRESH_KEY,
      { expiresIn: "365d" }
    );
  },

  //LOGIN
  loginUser: async (req, res) => {
    try {
      const user = await User.findOne({ username: req.body.username });
      if (!user) {
        return res.status(400).json("Wrong username!");
      }
      const validPassword = await bcrypt.compare(
        req.body.password,
        user.password
      );
      if (!validPassword) {
        return res.status(400).json("Wrong password");
      }
      if (user && validPassword) {
        const accessToken = authController.generateAccressToken(user);
        const refreshToken = authController.generateRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: false, //deloy lên thì để thành true
          path: "/",
          sameSite: "strict",
        });
        const { password, ...others } = user._doc;
        res.status(200).json({ ...others, accessToken });
      }
    } catch (err) {
      res.status(500).json(err);
    }
  },

  requestRefreshToken: async (req, res) => {
    //Take refresh token from user
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json("You are not authenticated");
    if (!refreshTokens.includes(refreshToken)) {
      return res.status(403).json("Refresh token in not valid");
    }
    jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
      if (err) {
        console.log(err);
        return res.status(403).json("Refresh token is not valid");
      }
      refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
      //create new accesstoken , refresh token
      const newAccessToken = authController.generateAccressToken(user);
      const newRefreshToken = authController.generateRefreshToken(user);
      refreshTokens.push(newRefreshToken);
      res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: false, //deloy lên thì để thành true
        path: "/",
        sameSite: "strict",
      });
      res.status(200).json({ accessToken: newAccessToken });
    });
  },

  //Đổi mật khẩu

  changePassword: async (req, res) => {
    //Check lại sau này kiểm tra email
    try {
      const { newPassword } = req.body;
      // Mã hóa mật khẩu mới và lưu vào cơ sở dữ liệu
      // Kiểm tra tính hợp lệ của resetToken
      if (
        User.resetToken !== resetToken ||
        Date.now() > User.resetTokenExpiration
      ) {
        return res.status(400).json("Invalid or expired reset token");
      }

      // Mã hóa mật khẩu mới và lưu vào cơ sở dữ liệu
      const salt = await bcrypt.genSalt(10);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);
      User.password = hashedNewPassword;

      // Xóa resetToken và resetTokenExpiration sau khi thay đổi mật khẩu
      User.resetToken = undefined;
      User.resetTokenExpiration = undefined;

      await user.save();

      // Gửi email xác nhận

      res.status(200).json("Password reset successfully");
    } catch (error) {
      console.error(error);
      res.status(500).json(error.message || "Internal Server Error");
    }
  },

  //LOG OUT
  userLogout: async (req, res) => {
    res.clearCookie("refreshToken");
    refreshTokens = refreshTokens.filter(
      (token) => token !== req.cookies.refreshToken
    );
    res.status(200).json("Logged out !");
  },
};

module.exports = authController;
