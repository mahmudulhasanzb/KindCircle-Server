import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, Db } from 'mongodb';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/kindcircle';

// Middlewares
app.use(cors());
app.use(express.json());

// Database connection
let db: Db;
const client = new MongoClient(MONGODB_URI);

async function connectDB() {
  try {
    await client.connect();
    db = client.db();
    console.log('Successfully connected to MongoDB.');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
}

// Interfaces matching database schema (Architecture Sec 5 & Tasks)
export interface User {
  _id?: any;
  name: string;
  email: string;
  photoUrl: string;
  role: 'supporter' | 'creator' | 'admin';
  credits: number;
  createdAt: Date;
}

export interface Campaign {
  _id?: any;
  title: string;
  story: string;
  category: string;
  funding_goal: number;
  minimum_contribution: number;
  deadline: Date;
  reward_info: string;
  image_url: string;
  creatorId: string;
  creator_name: string;
  creator_email: string;
  amount_raised: number;
  status: 'pending' | 'approved' | 'rejected';
  createdAt: Date;
}

export interface Contribution {
  _id?: any;
  campaignId: string;
  campaignTitle: string;
  supporter_email: string;
  creator_email: string;
  amount: number;
  status: 'pending' | 'approved' | 'rejected';
  createdAt: Date;
}

export interface Withdrawal {
  _id?: any;
  creator_email: string;
  withdrawal_credit: number;
  withdrawal_amount: number;
  status: 'pending' | 'approved' | 'rejected';
  payment_method: string;
  account_number: string;
  createdAt: Date;
}

export interface Notification {
  _id?: any;
  toEmail: string;
  message: string;
  actionRoute: string;
  time: Date;
}

export interface Report {
  _id?: any;
  campaignId: string;
  reporterName: string;
  reporterEmail: string;
  reason: string;
  createdAt: Date;
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    database: db ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

// Start server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
