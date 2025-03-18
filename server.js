const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const Tesseract = require('tesseract.js');
const fs = require('fs');
const fsPromises = fs.promises;
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

// Initialize Express app
const app = express();

// Store OTPs temporarily (in production, use Redis)
const otpStore = new Map();

// Create uploads directory
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/evoting')
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    aadharNumber: {
        type: String,
        unique: true,
        sparse: true
    },
    dob: Date,
    state: String,
    district: String,
    city: String,
    isVerified: {
        type: Boolean,
        default: false
    },
    lastLogin: Date,
    documents: {
        aadharCard: String,
        faceImage: String
    },
    isAdmin: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Reset Token Schema
const resetTokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600 // Token expires after 1 hour
    }
});

const ResetToken = mongoose.model('ResetToken', resetTokenSchema);

// Voter Schema
const voterSchema = new mongoose.Schema({
    voterId: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    age: Number,
    gender: String,
    constituency: String,
    pollingStationNumber: String,
    pollingStationName: String,
    pollingStationAddress: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Voter = mongoose.model('Voter', voterSchema);

// Vote Schema to track votes
const voteSchema = new mongoose.Schema({
    voterId: {
        type: String,
        required: true,
        unique: true // Ensures each voter can only vote once
    },
    party: {
        type: String,
        required: true,
        enum: ['BJP', 'Congress', 'AAP', 'NOTA'] // Only allow valid voting options
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    pollingStation: {
        type: String
    },
    constituency: {
        type: String
    }
});

const Vote = mongoose.model('Vote', voteSchema);

// Email Configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Auth middleware for admin routes
const adminAuth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        
        if (!decoded.isAdmin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        req.userData = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Authentication failed' });
    }
};

// Helper Functions
function generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
}

async function performOCR(imagePath) {
    try {
        const result = await Tesseract.recognize(
            imagePath,
            'eng',
            {
                logger: m => console.log(m),
                tessedit_char_whitelist: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ '
            }
        );
        return result.data.text;
    } catch (error) {
        console.error('OCR Error:', error);
        throw new Error('Failed to perform OCR on image');
    }
}

async function extractAadharNumber(text) {
    const aadharPattern = /[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}/g;
    const numbers = text.match(aadharPattern);
   
    if (!numbers || numbers.length === 0) {
        const noSpacePattern = /[2-9]{1}[0-9]{11}/g;
        const noSpaceNumbers = text.match(noSpacePattern);
       
        if (!noSpaceNumbers || noSpaceNumbers.length === 0) {
            return null;
        }
       
        const number = noSpaceNumbers[0];
        return `${number.substr(0,4)} ${number.substr(4,4)} ${number.substr(8)}`;
    }
   
    return numbers[0];
}

async function storeExtractedData(data, type) {
    const filePath = path.join(__dirname, `extracted_${type}.json`);
    try {
        let existingData = [];
        if (fs.existsSync(filePath)) {
            const fileContent = await fsPromises.readFile(filePath, 'utf8');
            existingData = JSON.parse(fileContent);
        }
       
        existingData.push({
            value: data,
            timestamp: new Date().toISOString(),
            source: type
        });

        await fsPromises.writeFile(filePath, JSON.stringify(existingData, null, 2));
        console.log(`${type} data stored successfully`);
    } catch (error) {
        console.error(`Error storing ${type} data:`, error);
        throw error;
    }
}

// Function to create admin user
async function createAdminUser() {
    try {
        // Admin user details
        const adminEmail = 'evotingsystem25@gmail.com';
        const adminPassword = 'Evsadmin@123'; // Change this to a strong password
        const adminAadhar = '963852741963'; // Use a placeholder or real Aadhar
        
        // Check if admin user already exists
        const existingAdmin = await User.findOne({ email: adminEmail });
        if (existingAdmin) {
            console.log('Admin user already exists');
            return;
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(adminPassword, 12);
        
        // Create admin user
        const adminUser = new User({
            name: 'System Administrator',
            email: adminEmail,
            password: hashedPassword,
            aadharNumber: adminAadhar,
            isVerified: true,
            isAdmin: true,
            dob: new Date('1990-01-01')
        });
        
        await adminUser.save();
        console.log('Admin user created successfully');
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Admin Creation Endpoint
app.post('/api/create-admin', async (req, res) => {
    try {
        // Only allow this in development mode or with a secret key
        const secretKey = req.headers['admin-secret-key'];
        if (process.env.NODE_ENV !== 'development' && secretKey !== process.env.ADMIN_SECRET_KEY) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized to create admin user'
            });
        }
        
        await createAdminUser();
        
        res.status(200).json({
            success: true,
            message: 'Admin user creation process completed'
        });
    } catch (error) {
        console.error('Admin creation endpoint error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during admin creation'
        });
    }
});

// Endpoints
app.post('/api/extract-aadhar', upload.single('aadharCard'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({
            success: false,
            error: 'No file uploaded'
        });
    }

    try {
        const text = await performOCR(req.file.path);
        const aadharNumber = await extractAadharNumber(text);

        if (!aadharNumber) {
            return res.status(400).json({
                success: false,
                error: 'Could not extract valid Aadhar number from image'
            });
        }

        await storeExtractedData(aadharNumber, 'aadhar');

        res.json({
            success: true,
            aadharNumber,
            filePath: req.file.path
        });
    } catch (error) {
        console.error('Aadhar extraction error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process Aadhar card'
        });
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, aadhar } = req.body;

        if (!email || !password || !aadhar) {
            return res.status(400).json({
                success: false,
                message: 'Email, password and Aadhar number are required'
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        if (user.aadharNumber && user.aadharNumber !== aadhar.replace(/\s/g, '')) {
            return res.status(401).json({
                success: false,
                message: 'Invalid Aadhar number'
            });
        }

        // Check if user is admin
        const isAdmin = user.isAdmin || false;

        // Generate and send OTP
        const otp = generateOTP();
        otpStore.set(email, {
            otp,
            expiry: Date.now() + 5 * 60 * 1000,
            isAdmin
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'E-Voting System Login OTP',
            html: `
                <h2>E-Voting System Login Verification</h2>
                <p>Your OTP for login is: <strong>${otp}</strong></p>
                <p>This OTP will expire in 5 minutes.</p>
                <p>If you didn't request this OTP, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        user.lastLogin = new Date();
        await user.save();

        res.json({
            success: true,
            message: 'Login successful. Please check your email for OTP.',
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                isAdmin
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during login'
        });
    }
});

// Registration Endpoint
app.post('/api/register', upload.fields([
    { name: 'aadharCard', maxCount: 1 },
    { name: 'faceImage', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, email, password, dob, state, district, city } = req.body;

        const hashedPassword = await bcrypt.hash(password, 12);
       
        const user = new User({
            name,
            email,
            password: hashedPassword,
            dob: new Date(dob),
            state,
            district,
            city,
            documents: {
                aadharCard: req.files.aadharCard ? req.files.aadharCard[0].path : null,
                faceImage: req.files.faceImage ? req.files.faceImage[0].path : null
            }
        });

        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '24h' }
        );

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                state: user.state,
                district: user.district,
                city: user.city
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            error: 'An error occurred during registration'
        });
    }
});

// OTP Verification Endpoint
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        const storedOTPData = otpStore.get(email);

        if (!storedOTPData) {
            return res.status(400).json({ error: 'OTP expired or not found' });
        }

        if (Date.now() > storedOTPData.expiry) {
            otpStore.delete(email);
            return res.status(400).json({ error: 'OTP expired' });
        }

        if (otp !== storedOTPData.otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        otpStore.delete(email);

        const user = await User.findOne({ email });
        const token = jwt.sign(
            { 
                userId: user._id, 
                email: user.email,
                isAdmin: storedOTPData.isAdmin || false 
            },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isAdmin: storedOTPData.isAdmin || false
            }
        });

    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

// Forgot Password Endpoint
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'No account found with this email' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        await ResetToken.findOneAndDelete({ userId: user._id });
        await new ResetToken({
            userId: user._id,
            token: resetToken
        }).save();

        const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:5500'}/reset-password.html?token=${resetToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request - E-Voting System',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #1a2980;">E-Voting System Password Reset</h2>
                    <p>You recently requested to reset your password. Click the button below to reset it:</p>
                    <div style="text-align: center; margin: 25px 0;">
                        <a href="${resetLink}" 
                           style="background-color: #1a2980; 
                                  color: white; 
                                  padding: 12px 24px; 
                                  text-decoration: none; 
                                  border-radius: 5px;
                                  display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    <p>This link will expire in 1 hour for security reasons.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                    <hr style="border: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">This is an automated message, please do not reply.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        res.json({
            success: true,
            message: 'Password reset link sent successfully'
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            error: 'Failed to process password reset request'
        });
    }
});

// Add Voter Endpoint (for admin) - Updated with adminAuth middleware
app.post('/api/admin/add-voter', adminAuth, async (req, res) => {
    try {
        const {
            voterId,
            name,
            age,
            gender,
            constituency,
            pollingStationNumber,
            pollingStationName,
            pollingStationAddress
        } = req.body;

        // Validate required fields
        if (!voterId || !name) {
            return res.status(400).json({
                success: false,
                message: 'Voter ID and Name are required fields'
            });
        }

        // Check if voter already exists
        const existingVoter = await Voter.findOne({ voterId });
        if (existingVoter) {
            return res.status(400).json({
                success: false,
                message: 'Voter with this ID already exists'
            });
        }

        // Create new voter
        const voter = new Voter({
            voterId,
            name,
            age: age || null,
            gender: gender || '',
            constituency: constituency || '',
            pollingStationNumber: pollingStationNumber || '',
            pollingStationName: pollingStationName || '',
            pollingStationAddress: pollingStationAddress || ''
        });

        // Save voter to database
        await voter.save();

        res.status(201).json({
            success: true,
            message: 'Voter added successfully',
            voter
        });
    } catch (error) {
        console.error('Add voter error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while adding voter'
        });
    }
});

// Voter Lookup Endpoint
app.post('/api/voter-lookup', async (req, res) => {
    try {
        const { voterId } = req.body;
        
        if (!voterId) {
            return res.status(400).json({
                success: false,
                message: 'Voter ID is required'
            });
        }
        
        const voter = await Voter.findOne({ voterId });
        
        if (!voter) {
            return res.status(404).json({
                success: false,
                message: 'Voter not found. Please check your Voter ID.'
            });
        }
        
        res.json({
            success: true,
            voter: {
                voterId: voter.voterId,
                name: voter.name,
                age: voter.age || 'Not specified',
                gender: voter.gender || 'Not specified',
                constituency: voter.constituency || 'Not specified',
                pollingStationNumber: voter.pollingStationNumber || 'Not specified',
                pollingStationName: voter.pollingStationName || 'Not specified',
                pollingStationAddress: voter.pollingStationAddress || 'Not specified'
            }
        });
    } catch (error) {
        console.error('Voter lookup error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while fetching voter information'
        });
    }
});

// Reset Password Endpoint
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ 
                success: false,
                error: 'Token and new password are required' 
            });
        }
        
        const resetTokenDoc = await ResetToken.findOne({ token });
        if (!resetTokenDoc) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid or expired reset token' 
            });
        }
        
        const user = await User.findById(resetTokenDoc.userId);
        if (!user) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found' 
            });
        }
        
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        await user.save();
        
        // Delete the used token
        await ResetToken.findByIdAndDelete(resetTokenDoc._id);
        
        res.json({
            success: true,
            message: 'Password has been reset successfully'
        });
        
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset password'
        });
    }
});

// Cast Vote Endpoint
app.post('/api/cast-vote', async (req, res) => {
    try {
        const { voterId, party, pollingStation, constituency } = req.body;
        
        if (!voterId || !party) {
            return res.status(400).json({
                success: false,
                message: 'Voter ID and party selection are required'
            });
        }
        
        // Check if voter exists
        const voter = await Voter.findOne({ voterId });
        if (!voter) {
            return res.status(404).json({
                success: false,
                message: 'Voter not found. Please verify your voter ID.'
            });
        }
        
        // Check if voter has already voted
        const existingVote = await Vote.findOne({ voterId });
        if (existingVote) {
            return res.status(409).json({
                success: false,
                message: 'You have already cast your vote.'
            });
        }
        
        // Create and save the vote
        const vote = new Vote({
            voterId,
            party,
            pollingStation: pollingStation || voter.pollingStationName,
            constituency: constituency || voter.constituency
        });
        
        await vote.save();
        
        // Return success
        res.status(201).json({
            success: true,
            message: 'Your vote has been successfully recorded.',
            voteId: vote._id
        });
        
    } catch (error) {
        console.error('Vote casting error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while processing your vote.'
        });
    }
});

// Get vote counts endpoint (for displaying results)
app.get('/api/vote-counts', async (req, res) => {
    try {
        // Aggregate votes by party
        const voteCounts = await Vote.aggregate([
            {
                $group: {
                    _id: '$party',
                    count: { $sum: 1 }
                }
            },
            {
                $project: {
                    party: '$_id',
                    count: 1,
                    _id: 0
                }
            }
        ]);
        
        // Format the result as an object
        const result = {};
        voteCounts.forEach(item => {
            result[item.party] = item.count;
        });
        
        // Add missing parties with zero counts
        ['BJP', 'Congress', 'AAP', 'NOTA'].forEach(party => {
            if (!result[party]) {
                result[party] = 0;
            }
        });
        
        res.json({
            success: true,
            counts: result,
            totalVotes: Object.values(result).reduce((a, b) => a + b, 0)
        });
        
    } catch (error) {
        console.error('Vote count fetch error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while fetching vote counts.'
        });
    }
});

// Check if voter has already voted
app.post('/api/check-voter-status', async (req, res) => {
    try {
        const { voterId } = req.body;
        
        if (!voterId) {
            return res.status(400).json({
                success: false,
                message: 'Voter ID is required'
            });
        }
        
        // Check if vote exists for this voter
        const existingVote = await Vote.findOne({ voterId });
        
        res.json({
            success: true,
            hasVoted: existingVote ? true : false,
            party: existingVote ? existingVote.party : null
        });
        
    } catch (error) {
        console.error('Voter status check error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while checking voter status'
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                success: false,
                error: 'File size too large. Maximum size is 5MB'
            });
        }
        return res.status(400).json({
            success: false,
            error: 'File upload error'
        });
    }
    
    res.status(500).json({
        success: false,
        error: 'Something broke on the server!'
    });
});

// Automatically create admin user when server starts
createAdminUser().then(() => {
    console.log('Admin user verification completed');
}).catch(err => {
    console.error('Error during admin user verification:', err);
});

// Start server
const PORT = process.env.PORT || 5500;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});