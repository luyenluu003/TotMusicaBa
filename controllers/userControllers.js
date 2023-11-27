const User = require("../models/user");

const userControllers = {
  //get all users
  getAllUsers: async (req, res) => {
    try {
      const user = await User.find();
      res.status(200).json(user);
    } catch (err) {
      res.status(500).json(err);
    }
  },
  // get user by ID
  getUserById: async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      res.status(200).json(user);
    } catch (err) {
      res.status(500).json(err);
    }
  },

  // delete user
  deleteUser: async (req, res) => {
    try {
      const user = await User.findByIdAndDelete(req.params.id);
      res.status(200).json("Delete successfully");
    } catch (err) {
      res.status(500).json(err);
    }
  },

  // update user
  updateUser: async (req, res) => {
    const { username } = req.body;
    try {
      const user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({ message: "Người dùng không tồn tại" });
      }

      if (user.username === username) {
        return res.status(200).json({
          message: "Không có thay đổi nào cần cập nhật",
          user: { id: user._id, username: user.username },
        });
      }

      const existingUser = await User.findOne({ username });

      if (existingUser && existingUser._id.toString() !== user._id.toString()) {
        return res.status(400).json({
          message: "Username đã tồn tại, vui lòng chọn một username khác",
        });
      }

      user.username = username;

      await user.save();

      res.status(200).json({
        message: "Cập nhật thông tin người dùng thành công",
        user: { id: user._id, username: user.username },
      });
    } catch (error) {
      console.error("Lỗi khi cập nhật thông tin người dùng:", error);
      res.status(500).json({ message: "Lỗi server" });
    }
  },
};
module.exports = userControllers;
