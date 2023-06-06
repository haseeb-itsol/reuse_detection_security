const express = require("express");
const {
  registerUser,
  verifyAccount,
  login,
  forgotPassword,
  verifyPasswordOtp,
  sendVerificationOtp,
  resetPassword,
  genRefreshToken,
} = require("../controller/authController");
const { protect } = require("../middleware/handleAuth");
const { docUpload } = require("../utils/multer.s3.util");
const authRouter = express.Router();

authRouter.route("/user").post(docUpload, registerUser);

authRouter.route("/forgot-password").post(forgotPassword);

authRouter.route("/verify-forgot-otp").post(verifyPasswordOtp);

authRouter.route("/reset-password").post(resetPassword);

authRouter.route("/gen-access-token").post(genRefreshToken);

authRouter.route("/verify-account").post(protect, verifyAccount);

authRouter.route("/send-verifcation-otp").post(protect, sendVerificationOtp);

authRouter.route("/login").post(login);

module.exports = authRouter;
