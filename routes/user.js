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
// get user by ID
router.get(
  "/:id",
  middlewareController.verifyToken,
  userControllers.getUserById
);
// update user
router.put(
  "/:id",
  middlewareController.verifyToken,
  userControllers.updateUser
);

module.exports = router;
