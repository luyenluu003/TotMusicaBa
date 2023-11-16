const express = require("express");
const cors = require("cors");
const app = express();
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const authRoute = require("./routes/auth.js");
const userRoute = require("./routes/user");
const bodyParser = require("body-parser");
const emailRoutes = require("./routes/email.js");
dotenv.config();

mongoose.connect(process.env.MONGODB_URL, () => {
  console.log("conected to mongo db");
});

app.use(cors());
app.use(cookieParser());
app.use(express.json());

//Email
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//ROUTES

app.use("/v1/auth", authRoute);
app.use("/v1/user", userRoute);
app.use("/email", emailRoutes);

app.listen(8000, () => {
  console.log("server is running");
});

//JSON WEB TOKEN

//AUTHENTICATION

//AUTHORIZATION
