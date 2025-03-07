//IMPORTS
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import connectDB from './config/db.js';
import authRoutes from './routes/Auth.routes.js';
//CONFIGURATION
const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));
dotenv.config();
const port = process.env.PORT || 5000;
//CONNECTION
connectDB();
//ENDPOINTS
app.use("/api/auth", authRoutes);
//SERVER
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});