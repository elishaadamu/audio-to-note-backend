import "dotenv/config";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-super-secret-key-donot-use-in-production';
export const hashPassword = async (password) => {
    return await bcrypt.hash(password, 10);
};
export const comparePassword = async (password, hashed) => {
    return await bcrypt.compare(password, hashed);
};
export const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
};
export const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    }
    catch (error) {
        return null;
    }
};
