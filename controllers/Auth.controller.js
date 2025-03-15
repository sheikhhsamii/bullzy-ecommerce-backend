import UserModel from "../models/User.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer/mail.js";
// Register Controller
const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please fill all the fields",
            });
        }
        // Check if user already exists
        const userExists = await UserModel.findOne({ email });
        if (userExists) {
            return res.status(400).json({
                success: false,
                message: "User already exists",
            });
        }
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Create user
        const user = await UserModel.create({
            name,
            email,
            password: hashedPassword,
        });
        // Generate token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to Bullzy",
            text: `Hello ${name},\n\nWelcome to Bullzy. We're excited to have you on board.\n\nBest regards,\nBullzy Team`,
        };

        await transporter.sendMail(mailOptions);
        return res.status(201).json({
            success: true,
            message: "User created successfully",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
            },
            token,
        });
    } catch (error) {
        console.error("Registration Error:", error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
};
// Login Controller
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please fill all the fields",
            });
        }
        // Check if user exists
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User does not exist",
            });
        }
        // Check if password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({
                success: false,
                message: "Invalid credentials",
            });
        }
        // Generate token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        // Send response
        return res.status(200).json({
            success: true,
            message: "User logged in successfully",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
            },
            token,
        });
    } catch (error) {
        console.error("Login Error:", error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
};

//Logout Controller
const logout = async (req, res) => {
    try {
        res.clearCookie("token");
        return res.status(200).json({
            success: true,
            message: "User logged out successfully",
        });
    } catch (error) {
        console.error("Logout Error:", error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
};

// Verify OTP Controller
const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await UserModel.findById(userId);
        if (!user) {
            return res
                .status(404)
                .json({ success: false, message: "User not found" });
        }
        if (user?.isAccountVerified) {
            return res
                .status(400)
                .json({ success: false, message: "User already verified" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.verifyOtp = otp;
        user.verifyOtpExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

        await user?.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user?.email,
            subject: "Verify your email",
            text: `Your verification code is ${otp}`,
        };
        await transporter.sendMail(mailOptions);
        return res
            .status(200)
            .json({ success: true, message: "OTP sent successfully" });
    } catch (error) {
        console.log(error, "send-verify-otp-error");
        res.status(500).json({
            success: false,
            message: error.message || "Something went wrong",
        });
    }
};

// Verify Email Controller
const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;
    console.log(userId, otp, "verify-email-controller");
    if (!userId || !otp) {
        return res
            .status(400)
            .json({ success: false, message: "Please provide all the fields" });
    }
    try {
        const user = await UserModel.findById(userId);
        if (!user) {
            return res
                .status(400)
                .json({ success: false, message: "User does not exist" });
        }
        if (user.verifyOtp === "" || user.verifyOtp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }
        if (user.verifyOtpExpires < Date.now()) {
            return res.status(400).json({ success: false, message: "OTP expired" });
        }
        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpires = 0;
        await user.save();
        return res
            .status(200)
            .json({ success: true, message: "Email verified successfully" });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message || "Verify Email, Something went wrong",
        });
    }
};

// check if user is authenticated
const isAuthenticated = async (req, res) => {
    try {
        return res.status(200).json({
            success: true,
            message: "User is authenticated",
        });
    } catch (error) {
        console.log(error, "isAuthenticated-error");
        return res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
};

//Send Reset Password OTP
const sendResetPasswordOTP = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res
            .status(400)
            .json({ success: false, message: "Please provide all the fields" });
    }
    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res
                .status(404)
                .json({ success: false, message: "User not found" });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user?.email,
            subject: "Reset your password",
            text: `Your reset password code is ${otp}`,
        };
        await transporter.sendMail(mailOptions);
        return res
            .status(200)
            .json({ success: true, message: "OTP sent successfully" });
    } catch (error) {
        console.log(error, "send-reset-password-otp-error");
        res.status(500).json({
            success: false,
            message: error.message || "Something went wrong",
        });
    }
};

//Verify Reset Password OTP
const verifyResetPasswordOTP = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
        return res
            .status(400)
            .json({ success: false, message: "Please provide all the fields" });
    }
    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res
                .status(404)
                .json({ success: false, message: "User not found" });
        }
        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.status(400).json({ success: false, message: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        await user.save();
        return res
            .status(200)
            .json({ success: true, message: "Password reset successfully" });
    } catch (error) {
        console.log(error, "verify-reset-password-otp-error");
        res.status(500).json({
            success: false,
            message: error.message || "Something went wrong",
        });
    }
};
export {
    register,
    login,
    logout,
    sendVerifyOtp,
    verifyEmail,
    isAuthenticated,
    sendResetPasswordOTP,
    verifyResetPasswordOTP,
};
