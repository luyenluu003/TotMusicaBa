const authController = require("../controllers/authControllers");
const middlewareController = require("../controllers/middlewareController");

const router = require("express").Router();

//REGISTER
router.post("/register", authController.regisrterUser);

//LOGIN
router.post("/login", authController.loginUser);

//RERESH
router.post("/refresh", authController.requestRefreshToken);

//LOG OUT
router.post(
  "/logout",
  middlewareController.verifyToken,
  authController.userLogout
);

//CHANGE PASSWORD
router.post("/changepassword", authController.changePassword);

module.exports = router;
