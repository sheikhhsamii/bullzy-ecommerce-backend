import { Router } from "express";
import {
    isAuthenticated,
    login,
    logout,
    register,
    sendResetPasswordOTP,
    sendVerifyOtp,
    verifyEmail,
    verifyResetPasswordOTP,
} from "../controllers/Auth.controller.js";
import { userAuth } from "../middleware/userAuth.js";
const router = Router();
router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.post("/send-verify-otp", userAuth, sendVerifyOtp);
router.post("/verify-otp", userAuth, verifyEmail);
router.post("/is-auth", userAuth, isAuthenticated);
router.post("/send-reset-password-otp", sendResetPasswordOTP);
router.post("/verify-reset-password-otp", verifyResetPasswordOTP);

export default router;
