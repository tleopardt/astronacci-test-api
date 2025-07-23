import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth';

const app = express();

// Middlewares
app.use(cors()); // Enable CORS globally
app.use(express.json());

// Routes
app.use('/api', authRoutes);

// Uploaded Image
app.use('/uploads', express.static('uploads'));

export default app;
