import mongoose from 'mongoose';

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(`MongoDB Connected: ${conn.connection.host} has been connected successfully! `);
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
};

export default connectDB;