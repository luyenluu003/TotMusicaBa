const middlewareController = require("../controllers/middlewareController");
const userControllers = require("../controllers/userControllers");

const router = require("express").Router();

//get all users
router.get("/", middlewareController.verifyToken, userControllers.getAllUsers);

//delete user
router.delete(
  "/:id",
  middlewareController.verifyTokenAndAdminAuth,
  userControllers.deleteUser
);

module.exports = router;
