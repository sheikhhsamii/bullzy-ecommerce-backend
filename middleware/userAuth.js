import jwt from "jsonwebtoken";
export const userAuth = async (req, res, next) => {
    try {
        const { token } = req.cookies;
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded) {
            req.body.userId = decoded.id;
        } else {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }

        next();
    } catch (error) {
        console.error("User Auth Error:", error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
};
