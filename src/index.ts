import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, Db, ObjectId } from 'mongodb';
import { createRemoteJWKSet, jwtVerify } from 'jose-cjs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/kindcircle';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';

const JWKS = createRemoteJWKSet(
  new URL(`${CLIENT_URL}/api/auth/jwks`)
);

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

export interface AuthRequest extends express.Request {
  user?: {
    id: string;
    email: string;
    role: 'supporter' | 'creator' | 'admin';
    [key: string]: any;
  };
}

export const verifyToken = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);
    (req as AuthRequest).user = payload as any;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(401).json({ message: 'Unauthorized' });
  }
};

export const isSupporter = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = (req as AuthRequest).user;
  if (!user || user.role !== 'supporter') {
    res.status(403).json({ message: 'Forbidden' });
    return;
  }
  next();
};

export const isCreator = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = (req as AuthRequest).user;
  if (!user || user.role !== 'creator') {
    res.status(403).json({ message: 'Forbidden' });
    return;
  }
  next();
};

export const isAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = (req as AuthRequest).user;
  if (!user || user.role !== 'admin') {
    res.status(403).json({ message: 'Forbidden' });
    return;
  }
  next();
};

// Helper function to create database notifications
async function createNotification(toEmail: string, message: string, actionRoute: string) {
  try {
    const notificationDoc = {
      toEmail,
      message,
      actionRoute,
      time: new Date()
    };
    await db.collection('notifications').insertOne(notificationDoc);
    console.log(`Notification created for ${toEmail}: ${message}`);
  } catch (error) {
    console.error('Error creating notification:', error);
  }
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    database: db ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

// GET /api/stats/platform - Returns platform totals
app.get('/api/stats/platform', async (req, res) => {
  try {
    const usersCount = await db.collection('user').countDocuments();
    const campaignsCount = await db.collection('campaigns').countDocuments({ status: 'approved' });
    const creditsResult = await db.collection('campaigns').aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: null, totalCredits: { $sum: '$amount_raised' } } }
    ]).toArray();
    const totalCreditsRaised = creditsResult.length > 0 && creditsResult[0] ? creditsResult[0].totalCredits : 0;

    res.json({
      totalUsers: usersCount,
      totalCampaigns: campaignsCount,
      totalCreditsRaised,
    });
  } catch (error) {
    console.error('Error fetching platform stats:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/campaigns/top-funded - Returns top 6 approved campaigns by raised amount
app.get('/api/campaigns/top-funded', async (req, res) => {
  try {
    const campaigns = await db.collection('campaigns')
      .find({ status: 'approved' })
      .sort({ amount_raised: -1 })
      .limit(6)
      .toArray();

    res.json(campaigns);
  } catch (error) {
    console.error('Error fetching top funded campaigns:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/campaigns — approved, non-expired campaigns with optional filters
app.get('/api/campaigns', async (req, res) => {
  try {
    const { category, search, sort } = req.query as {
      category?: string;
      search?: string;
      sort?: string;
    };

    const now = new Date();

    // Build filter query
    const query: Record<string, any> = {
      status: 'approved',
      deadline: { $gt: now },
    };

    if (category && category !== 'all') {
      query.category = category;
    }

    if (search && search.trim() !== '') {
      query.$or = [
        { title: { $regex: search.trim(), $options: 'i' } },
        { story: { $regex: search.trim(), $options: 'i' } },
        { creator_name: { $regex: search.trim(), $options: 'i' } },
      ];
    }

    // Build sort
    let sortQuery: Record<string, 1 | -1> = { createdAt: -1 }; // default: newest
    if (sort === 'most-funded') {
      sortQuery = { amount_raised: -1 };
    } else if (sort === 'ending-soon') {
      sortQuery = { deadline: 1 };
    }

    const campaigns = await db.collection('campaigns')
      .find(query)
      .sort(sortQuery)
      .toArray();

    res.json(campaigns);
  } catch (error) {
    console.error('Error fetching campaigns:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/campaigns/:id — Return single campaign by ObjectId
app.get('/api/campaigns/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid campaign ID' });
      return;
    }

    const campaign = await db.collection('campaigns').findOne({ _id: new ObjectId(id) });
    if (!campaign) {
      res.status(404).json({ message: 'Campaign not found' });
      return;
    }

    const backerCount = await db.collection('contributions').countDocuments({ campaignId: id });

    res.json({
      ...campaign,
      backerCount: backerCount || 0,
    });
  } catch (error) {
    console.error('Error fetching campaign detail:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// POST /api/contributions (Supporter only) — Contribute credits to campaign
app.post('/api/contributions', verifyToken, isSupporter, async (req, res) => {
  try {
    const { campaignId, amount } = req.body as { campaignId: string; amount: number };
    const userEmail = (req as AuthRequest).user?.email;

    if (!campaignId || !ObjectId.isValid(campaignId)) {
      res.status(400).json({ message: 'Invalid or missing campaign ID' });
      return;
    }

    if (!amount || typeof amount !== 'number' || amount <= 0) {
      res.status(400).json({ message: 'Invalid contribution amount' });
      return;
    }

    // 1. Fetch Campaign
    const campaign = await db.collection('campaigns').findOne({ _id: new ObjectId(campaignId) });
    if (!campaign) {
      res.status(404).json({ message: 'Campaign not found' });
      return;
    }

    // 2. Validate Campaign Status & Deadline
    if (campaign.status !== 'approved') {
      res.status(400).json({ message: 'Campaign is not active or approved' });
      return;
    }

    if (new Date(campaign.deadline).getTime() < Date.now()) {
      res.status(400).json({ message: 'Campaign deadline has passed' });
      return;
    }

    // 3. Validate Minimum Contribution
    if (amount < campaign.minimum_contribution) {
      res.status(400).json({
        message: `Contribution must be at least ${campaign.minimum_contribution} credits`,
      });
      return;
    }

    // 4. Fetch Supporter
    const supporter = await db.collection('user').findOne({ email: userEmail });
    if (!supporter) {
      res.status(404).json({ message: 'Supporter user not found' });
      return;
    }

    // 5. Validate Supporter Credits
    const currentCredits = supporter.credits || 0;
    if (currentCredits < amount) {
      res.status(400).json({ message: 'Insufficient credits in supporter balance' });
      return;
    }

    // 6. Deduct Credits from Supporter
    await db.collection('user').updateOne(
      { _id: supporter._id },
      { $inc: { credits: -amount } }
    );

    // 7. Create Pending Contribution
    const contributionDoc = {
      campaignId: campaignId,
      campaignTitle: campaign.title,
      supporter_email: supporter.email,
      creator_email: campaign.creator_email,
      amount: amount,
      status: 'pending',
      createdAt: new Date(),
    };

    const insertResult = await db.collection('contributions').insertOne(contributionDoc);

    res.status(201).json({
      message: 'Contribution submitted successfully and is pending approval',
      contributionId: insertResult.insertedId,
      remainingCredits: currentCredits - amount,
    });
  } catch (error) {
    console.error('Error submitting contribution:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// POST /api/campaigns (Creator only) — Submit a new campaign
app.post('/api/campaigns', verifyToken, isCreator, async (req, res) => {
  try {
    const {
      title,
      story,
      category,
      funding_goal,
      minimum_contribution,
      deadline,
      reward_info,
      image_url,
    } = req.body as {
      title: string;
      story: string;
      category: string;
      funding_goal: number;
      minimum_contribution: number;
      deadline: string;
      reward_info: string;
      image_url: string;
    };

    const userEmail = (req as AuthRequest).user?.email;

    // 1. Validation
    if (!title || !title.trim()) {
      res.status(400).json({ message: 'Title is required' });
      return;
    }
    if (!story || !story.trim()) {
      res.status(400).json({ message: 'Story is required' });
      return;
    }
    if (!category || !category.trim()) {
      res.status(400).json({ message: 'Category is required' });
      return;
    }
    if (funding_goal === undefined || typeof funding_goal !== 'number' || funding_goal <= 0) {
      res.status(400).json({ message: 'Funding goal must be a positive number greater than 0' });
      return;
    }
    if (
      minimum_contribution === undefined ||
      typeof minimum_contribution !== 'number' ||
      minimum_contribution <= 0
    ) {
      res.status(400).json({ message: 'Minimum contribution must be a positive number greater than 0' });
      return;
    }
    if (!deadline) {
      res.status(400).json({ message: 'Deadline is required' });
      return;
    }
    const deadlineDate = new Date(deadline);
    if (isNaN(deadlineDate.getTime())) {
      res.status(400).json({ message: 'Invalid deadline date' });
      return;
    }
    if (deadlineDate.getTime() <= Date.now()) {
      res.status(400).json({ message: 'Deadline must be a future date' });
      return;
    }
    if (!reward_info || !reward_info.trim()) {
      res.status(400).json({ message: 'Reward info is required' });
      return;
    }
    if (!image_url || !image_url.trim()) {
      res.status(400).json({ message: 'Cover image URL is required' });
      return;
    }

    // 2. Fetch Creator Info
    const creator = await db.collection('user').findOne({ email: userEmail });
    if (!creator) {
      res.status(404).json({ message: 'Creator profile not found' });
      return;
    }

    // 3. Save Campaign
    const campaignDoc = {
      title: title.trim(),
      story: story.trim(),
      category: category.toLowerCase().trim(),
      funding_goal,
      minimum_contribution,
      deadline: deadlineDate,
      reward_info: reward_info.trim(),
      image_url: image_url.trim(),
      creatorId: creator._id.toString(),
      creator_name: creator.name || 'Anonymous',
      creator_email: creator.email,
      amount_raised: 0,
      status: 'pending',
      createdAt: new Date(),
    };

    const result = await db.collection('campaigns').insertOne(campaignDoc);

    res.status(201).json({
      message: 'Campaign created successfully and is pending admin approval',
      campaignId: result.insertedId,
    });
  } catch (error) {
    console.error('Error creating campaign:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/campaigns/creator/:userId — Fetch all campaigns by creator, sorted by deadline descending
app.get('/api/campaigns/creator/:userId', verifyToken, isCreator, async (req, res) => {
  try {
    const { userId } = req.params;
    const campaigns = await db.collection('campaigns')
      .find({ creatorId: userId })
      .sort({ deadline: -1 })
      .toArray();

    res.json(campaigns);
  } catch (error) {
    console.error('Error fetching creator campaigns:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// PUT /api/campaigns/:id (Creator only, verify ownership) — Update campaign details
app.put('/api/campaigns/:id', verifyToken, isCreator, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, story, reward_info } = req.body as {
      title?: string;
      story?: string;
      reward_info?: string;
    };
    const userEmail = (req as AuthRequest).user?.email;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid campaign ID' });
      return;
    }

    // 1. Fetch Campaign
    const campaign = await db.collection('campaigns').findOne({ _id: new ObjectId(id) });
    if (!campaign) {
      res.status(404).json({ message: 'Campaign not found' });
      return;
    }

    // 2. Verify Ownership
    if (campaign.creator_email !== userEmail) {
      res.status(403).json({ message: 'Forbidden: You do not own this campaign' });
      return;
    }

    // 3. Update Fields
    const updateFields: Record<string, string> = {};
    if (title && title.trim()) updateFields.title = title.trim();
    if (story && story.trim()) updateFields.story = story.trim();
    if (reward_info && reward_info.trim()) updateFields.reward_info = reward_info.trim();

    if (Object.keys(updateFields).length === 0) {
      res.status(400).json({ message: 'No fields to update' });
      return;
    }

    await db.collection('campaigns').updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );

    res.json({ message: 'Campaign updated successfully' });
  } catch (error) {
    console.error('Error updating campaign:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// DELETE /api/campaigns/:id (Creator only, verify ownership) — Delete campaign and refund contributors
app.delete('/api/campaigns/:id', verifyToken, isCreator, async (req, res) => {
  try {
    const { id } = req.params;
    const userEmail = (req as AuthRequest).user?.email;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid campaign ID' });
      return;
    }

    // 1. Fetch Campaign
    const campaign = await db.collection('campaigns').findOne({ _id: new ObjectId(id) });
    if (!campaign) {
      res.status(404).json({ message: 'Campaign not found' });
      return;
    }

    // 2. Verify Ownership
    if (campaign.creator_email !== userEmail) {
      res.status(403).json({ message: 'Forbidden: You do not own this campaign' });
      return;
    }

    // 3. Refund Approved Contributions
    const approvedContributions = await db.collection('contributions').find({
      campaignId: id,
      status: 'approved',
    }).toArray();

    for (const contrib of approvedContributions) {
      await db.collection('user').updateOne(
        { email: contrib.supporter_email },
        { $inc: { credits: contrib.amount } }
      );
    }

    // 4. Update all contributions for this campaign to rejected/refunded status
    await db.collection('contributions').updateMany(
      { campaignId: id },
      { $set: { status: 'rejected' } }
    );

    // 5. Delete Campaign
    await db.collection('campaigns').deleteOne({ _id: new ObjectId(id) });

    res.json({
      message: 'Campaign deleted successfully. Approved contributors refunded.',
      refundedBackers: approvedContributions.length,
    });
  } catch (error) {
    console.error('Error deleting campaign:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/contributions/pending/:creatorEmail (Creator only) — Fetch pending contributions to review
app.get('/api/contributions/pending/:creatorEmail', verifyToken, isCreator, async (req, res) => {
  try {
    const { creatorEmail } = req.params;
    const userEmail = (req as AuthRequest).user?.email;

    // Security check: Creators can only view their own pending contributions
    if (creatorEmail !== userEmail) {
      res.status(403).json({ message: 'Forbidden: You can only view your own contributions' });
      return;
    }

    const pendingContributions = await db.collection('contributions').aggregate([
      { $match: { creator_email: creatorEmail, status: 'pending' } },
      {
        $lookup: {
          from: 'user',
          localField: 'supporter_email',
          foreignField: 'email',
          as: 'supporter',
        },
      },
      {
        $unwind: {
          path: '$supporter',
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          _id: 1,
          campaignId: 1,
          campaignTitle: 1,
          supporter_email: 1,
          supporter_name: { $ifNull: ['$supporter.name', '$supporter_email'] },
          creator_email: 1,
          amount: 1,
          status: 1,
          createdAt: 1,
        },
      },
    ]).toArray();

    res.json(pendingContributions);
  } catch (error) {
    console.error('Error fetching pending contributions:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// PATCH /api/contributions/:id/approve (Creator only) — Approve a pending contribution
app.patch('/api/contributions/:id/approve', verifyToken, isCreator, async (req, res) => {
  try {
    const { id } = req.params;
    const userEmail = (req as AuthRequest).user?.email;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid contribution ID' });
      return;
    }

    // 1. Fetch Contribution
    const contrib = await db.collection('contributions').findOne({ _id: new ObjectId(id) });
    if (!contrib) {
      res.status(404).json({ message: 'Contribution not found' });
      return;
    }

    // 2. Validate Pending Status
    if (contrib.status !== 'pending') {
      res.status(400).json({ message: `Contribution is already ${contrib.status}` });
      return;
    }

    // 3. Verify Ownership
    if (contrib.creator_email !== userEmail) {
      res.status(403).json({ message: 'Forbidden: You do not own the campaign for this contribution' });
      return;
    }

    // 4. Update Status to Approved
    await db.collection('contributions').updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: 'approved' } }
    );

    // 5. Add to Campaign's amount_raised
    await db.collection('campaigns').updateOne(
      { _id: new ObjectId(contrib.campaignId) },
      { $inc: { amount_raised: contrib.amount } }
    );

    // Notify supporter about the approved contribution
    await createNotification(
      contrib.supporter_email,
      `Your contribution of ${contrib.amount} credits to "${contrib.campaignTitle}" has been approved.`,
      '/dashboard/supporter/contributions'
    );

    res.json({ message: 'Contribution approved successfully' });
  } catch (error) {
    console.error('Error approving contribution:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// PATCH /api/contributions/:id/reject (Creator only) — Reject a pending contribution (Refund)
app.patch('/api/contributions/:id/reject', verifyToken, isCreator, async (req, res) => {
  try {
    const { id } = req.params;
    const userEmail = (req as AuthRequest).user?.email;

    if (!ObjectId.isValid(id)) {
      res.status(400).json({ message: 'Invalid contribution ID' });
      return;
    }

    // 1. Fetch Contribution
    const contrib = await db.collection('contributions').findOne({ _id: new ObjectId(id) });
    if (!contrib) {
      res.status(404).json({ message: 'Contribution not found' });
      return;
    }

    // 2. Validate Pending Status
    if (contrib.status !== 'pending') {
      res.status(400).json({ message: `Contribution is already ${contrib.status}` });
      return;
    }

    // 3. Verify Ownership
    if (contrib.creator_email !== userEmail) {
      res.status(403).json({ message: 'Forbidden: You do not own the campaign for this contribution' });
      return;
    }

    // 4. Update Status to Rejected
    await db.collection('contributions').updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: 'rejected' } }
    );

    // 5. Refund credits to supporter balance
    await db.collection('user').updateOne(
      { email: contrib.supporter_email },
      { $inc: { credits: contrib.amount } }
    );

    // Notify supporter about the rejected contribution
    await createNotification(
      contrib.supporter_email,
      `Your contribution of ${contrib.amount} credits to "${contrib.campaignTitle}" has been rejected. Credits have been refunded to your balance.`,
      '/dashboard/supporter/contributions'
    );

    res.json({ message: 'Contribution rejected and credits refunded to supporter' });
  } catch (error) {
    console.error('Error rejecting contribution:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/contributions/supporter/:email — Paginated contributions by supporter
app.get('/api/contributions/supporter/:email', verifyToken, isSupporter, async (req, res) => {
  try {
    const { email } = req.params;
    const userEmail = (req as AuthRequest).user?.email;

    // Security check: Supporters can only view their own contributions
    if (email !== userEmail) {
      res.status(403).json({ message: 'Forbidden: You can only view your own contributions' });
      return;
    }

    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const skip = (page - 1) * limit;

    const query = { supporter_email: email };
    const total = await db.collection('contributions').countDocuments(query);

    const contributions = await db.collection('contributions').aggregate([
      { $match: query },
      { $sort: { createdAt: -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $lookup: {
          from: 'user',
          localField: 'creator_email',
          foreignField: 'email',
          as: 'creator',
        },
      },
      {
        $unwind: {
          path: '$creator',
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          _id: 1,
          campaignId: 1,
          campaignTitle: 1,
          supporter_email: 1,
          creator_email: 1,
          creator_name: { $ifNull: ['$creator.name', '$creator_email'] },
          amount: 1,
          status: 1,
          createdAt: 1,
        },
      },
    ]).toArray();

    res.json({
      contributions,
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      limit,
    });
  } catch (error) {
    console.error('Error fetching supporter contributions:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});






// GET /api/creator/stats/:userId — Creator dashboard stats (T-15.1)
app.get('/api/creator/stats/:userId', verifyToken, isCreator, async (req, res) => {
  try {
    const { userId } = req.params;
    const now = new Date();

    const totalCampaigns = await db.collection('campaigns').countDocuments({ creatorId: userId });
    const activeCampaigns = await db.collection('campaigns').countDocuments({
      creatorId: userId,
      status: 'approved',
      deadline: { $gt: now },
    });

    const raisedResult = await db.collection('campaigns').aggregate([
      { $match: { creatorId: userId } },
      { $group: { _id: null, totalRaised: { $sum: '$amount_raised' } } },
    ]).toArray();
    const totalRaised = raisedResult.length > 0 && raisedResult[0] ? raisedResult[0].totalRaised : 0;

    res.json({ totalCampaigns, activeCampaigns, totalRaised });
  } catch (error) {
    console.error('Error fetching creator stats:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/supporter/stats/:email — Supporter dashboard stats (T-15.3)
app.get('/api/supporter/stats/:email', verifyToken, isSupporter, async (req, res) => {
  try {
    const { email } = req.params;
    const userEmail = (req as AuthRequest).user?.email;

    if (email !== userEmail) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const totalContributions = await db.collection('contributions').countDocuments({ supporter_email: email });
    const pendingContributions = await db.collection('contributions').countDocuments({
      supporter_email: email,
      status: 'pending',
    });

    const approvedResult = await db.collection('contributions').aggregate([
      { $match: { supporter_email: email, status: 'approved' } },
      { $group: { _id: null, totalApproved: { $sum: '$amount' } } },
    ]).toArray();
    const totalApprovedAmount = approvedResult.length > 0 && approvedResult[0] ? approvedResult[0].totalApproved : 0;

    const approvedContributions = await db.collection('contributions').aggregate([
      { $match: { supporter_email: email, status: 'approved' } },
      { $sort: { createdAt: -1 } },
      {
        $lookup: {
          from: 'user',
          localField: 'creator_email',
          foreignField: 'email',
          as: 'creator',
        },
      },
      {
        $unwind: {
          path: '$creator',
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          _id: 1,
          campaignTitle: 1,
          amount: 1,
          creator_name: { $ifNull: ['$creator.name', '$creator_email'] },
          status: 1,
          createdAt: 1,
        },
      },
    ]).toArray();

    res.json({ totalContributions, pendingContributions, totalApprovedAmount, approvedContributions });
  } catch (error) {
    console.error('Error fetching supporter stats:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start server
connectDB().then(async () => {
  // Create indexes on campaigns collection (T-9.7)
  try {
    const campaignsCol = db.collection('campaigns');
    await Promise.all([
      campaignsCol.createIndex({ status: 1, createdAt: -1 }),
      campaignsCol.createIndex({ creatorId: 1 }),
      campaignsCol.createIndex({ category: 1 }),
      campaignsCol.createIndex({ amount_raised: -1 }),
      campaignsCol.createIndex({ deadline: 1 }),
    ]);
    console.log('Campaign indexes ensured.');
  } catch (err) {
    console.warn('Index creation warning:', err);
  }

  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});

