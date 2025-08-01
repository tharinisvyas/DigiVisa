// DigiVisa Backend API - Node.js with Express
// Package.json dependencies:
/*
{
  "name": "digivisa-backend",
  "version": "1.0.0",
  "description": "DigiVisa Backend API for document verification",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "multer": "^1.4.5-lts.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "tesseract.js": "^4.1.1",
    "sharp": "^0.32.5",
    "pdf-parse": "^1.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "joi": "^17.9.2",
    "winston": "^3.10.0",
    "express-rate-limit": "^6.10.0",
    "helmet": "^7.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
*/

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const sharp = require('sharp');
const Tesseract = require('tesseract.js');
const pdfParse = require('pdf-parse');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const Joi = require('joi');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Winston logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/digivisa', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    userType: { type: String, enum: ['applicant', 'agent', 'official'], required: true },
    profile: {
        fullName: String,
        phoneNumber: String,
        address: String,
        nationality: String
    },
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date,
    isActive: { type: Boolean, default: true }
});

// Application Schema
const applicationSchema = new mongoose.Schema({
    applicationId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'verified', 'failed', 'approved', 'rejected'], 
        default: 'pending' 
    },
    documents: {
        passport: {
            filename: String,
            path: String,
            uploadedAt: Date,
            ocrData: mongoose.Schema.Types.Mixed,
            verified: { type: Boolean, default: false },
            verificationErrors: [String]
        },
        photo: {
            filename: String,
            path: String,
            uploadedAt: Date,
            ocrData: mongoose.Schema.Types.Mixed,
            verified: { type: Boolean, default: false },
            verificationErrors: [String]
        },
        financial: {
            filename: String,
            path: String,
            uploadedAt: Date,
            ocrData: mongoose.Schema.Types.Mixed,
            verified: { type: Boolean, default: false },
            verificationErrors: [String]
        },
        invitation: {
            filename: String,
            path: String,
            uploadedAt: Date,
            ocrData: mongoose.Schema.Types.Mixed,
            verified: { type: Boolean, default: false },
            verificationErrors: [String]
        }
    },
    personalInfo: {
        fullName: String,
        passportNumber: String,
        dateOfBirth: Date,
        nationality: String,
        visaType: String,
        purposeOfVisit: String
    },
    verificationResults: {
        overallScore: Number,
        passportScore: Number,
        photoScore: Number,
        financialScore: Number,
        invitationScore: Number,
        governmentCompliance: Boolean,
        processingTime: Number
    },
    failureReasons: [String],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    completedAt: Date
});

// Models
const User = mongoose.model('User', userSchema);
const Application = mongoose.model('Application', applicationSchema);

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = `uploads/${req.user.id}/${Date.now()}/`;
        require('fs').mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + '.' + file.originalname.split('.').pop());
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = {
            passport: ['image/jpeg', 'image/jpg', 'image/png'],
            photo: ['image/jpeg', 'image/jpg'],
            financial: ['application/pdf'],
            invitation: ['application/pdf']
        };

        if (allowedTypes[file.fieldname] && allowedTypes[file.fieldname].includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`Invalid file type for ${file.fieldname}. Expected: ${allowedTypes[file.fieldname].join(', ')}`));
        }
    }
});

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Validation schemas
const loginSchema = Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
    userType: Joi.string().valid('applicant', 'agent', 'official').required()
});

const personalInfoSchema = Joi.object({
    fullName: Joi.string().required(),
    passportNumber: Joi.string().pattern(/^[A-Z][0-9]{7}$/).required(),
    dateOfBirth: Joi.date().required(),
    nationality: Joi.string().required(),
    visaType: Joi.string().required(),
    purposeOfVisit: Joi.string().required()
});

// Indian Government Verification Rules
class GovernmentVerificationEngine {
    static async verifyPassport(ocrData) {
        const errors = [];
        let score = 100;

        // Check required fields
        const requiredFields = ['passport_number', 'name', 'date_of_birth', 'issue_date', 'expiry_date'];
        for (const field of requiredFields) {
            if (!ocrData[field]) {
                errors.push(`Missing required field: ${field}`);
                score -= 20;
            }
        }

        // Passport number format validation (Indian passport: Letter + 7 digits)
        if (ocrData.passport_number && !/^[A-Z][0-9]{7}$/.test(ocrData.passport_number)) {
            errors.push('Invalid Indian passport number format');
            score -= 15;
        }

        // Expiry date validation (must be valid for at least 6 months)
        if (ocrData.expiry_date) {
            const expiryDate = new Date(ocrData.expiry_date);
            const sixMonthsFromNow = new Date();
            sixMonthsFromNow.setMonth(sixMonthsFromNow.getMonth() + 6);
            
            if (expiryDate < sixMonthsFromNow) {
                errors.push('Passport expires within 6 months - not eligible for visa');
                score -= 30;
            }
        }

        // Issue authority validation
        const validAuthorities = ['PASSPORT OFFICE', 'REGIONAL PASSPORT OFFICE'];
        if (ocrData.issuing_authority && !validAuthorities.some(auth => 
            ocrData.issuing_authority.toUpperCase().includes(auth))) {
            errors.push('Invalid issuing authority for Indian passport');
            score -= 10;
        }

        return { verified: errors.length === 0, score: Math.max(0, score), errors };
    }

    static async verifyPhoto(imageData, ocrData) {
        const errors = [];
        let score = 100;

        // Check if face is detected
        if (!ocrData.face_detected) {
            errors.push('No face detected in the photograph');
            score -= 40;
        }

        // Background color check
        if (ocrData.background_color !== 'WHITE') {
            errors.push('Photo background must be pure white as per Indian government standards');
            score -= 25;
        }

        // Dimension check
        if (ocrData.dimensions !== '35x45mm') {
            errors.push('Photo dimensions must be 35mm x 45mm as per specifications');
            score -= 20;
        }

        // Quality score
        if (ocrData.quality_score < 80) {
            errors.push('Photo quality is below acceptable standards');
            score -= 15;
        }

        return { verified: errors.length === 0, score: Math.max(0, score), errors };
    }

    static async verifyFinancialDocument(ocrData) {
        const errors = [];
        let score = 100;

        // Check if it's from an Indian bank
        const indianBanks = ['STATE BANK OF INDIA', 'HDFC BANK', 'ICICI BANK', 'AXIS BANK', 'PUNJAB NATIONAL BANK'];
        if (!ocrData.bank_name || !indianBanks.some(bank => 
            ocrData.bank_name.toUpperCase().includes(bank))) {
            errors.push('Bank statement must be from a recognized Indian bank');
            score -= 30;
        }

        // Minimum balance check (₹2,00,000)
        if (ocrData.balance) {
            const balance = parseFloat(ocrData.balance.replace(/[₹,]/g, ''));
            if (balance < 200000) {
                errors.push('Minimum balance requirement of ₹2,00,000 not maintained');
                score -= 40;
            }
        }

        // Statement period check
        if (ocrData.statement_period !== '6 MONTHS') {
            errors.push('Bank statement must cover the last 6 months');
            score -= 20;
        }

        // Account holder name should match passport
        if (!ocrData.account_holder) {
            errors.push('Account holder name not clearly visible');
            score -= 10;
        }

        return { verified: errors.length === 0, score: Math.max(0, score), errors };
    }

    static async verifyInvitationLetter(ocrData) {
        const errors = [];
        let score = 100;

        // Required fields check
        const requiredFields = ['inviting_party', 'purpose', 'duration', 'address', 'contact'];
        for (const field of requiredFields) {
            if (!ocrData[field]) {
                errors.push(`Missing required field: ${field}`);
                score -= 20;
            }
        }

        // Company/organization check
        if (!ocrData.company) {
            errors.push('Official letterhead with company/organization details required');
            score -= 25;
        }

        // Contact details validation
        if (ocrData.contact && !/\+\d{1,3}-\d{3}-\d{4}/.test(ocrData.contact)) {
            errors.push('Invalid contact number format');
            score -= 10;
        }

        // Purpose clarity
        const validPurposes = ['BUSINESS', 'CONFERENCE', 'MEETING', 'TRAINING', 'TOURISM'];
        if (ocrData.purpose && !validPurposes.some(purpose => 
            ocrData.purpose.toUpperCase().includes(purpose))) {
            errors.push('Purpose of visit not clearly defined');
            score -= 15;
        }

        return { verified: errors.length === 0, score: Math.max(0, score), errors };
    }
}

// OCR Processing Engine
class OCREngine {
    static async processImage(imagePath) {
        try {
            const { data: { text } } = await Tesseract.recognize(imagePath, 'eng', {
                logger: m => logger.info(`OCR Progress: ${m.status} ${m.progress}`)
            });
            return text;
        } catch (error) {
            logger.error('OCR processing failed:', error);
            throw new Error('OCR processing failed');
        }
    }

    static async processPDF(pdfPath) {
        try {
            const dataBuffer = require('fs').readFileSync(pdfPath);
            const data = await pdfParse(dataBuffer);
            return data.text;
        } catch (error) {
            logger.error('PDF processing failed:', error);
            throw new Error('PDF processing failed');
        }
    }

    static extractPassportData(text) {
        const data = {};
        
        // Extract passport number (Indian format: Letter + 7 digits)
        const passportMatch = text.match(/[A-Z]\d{7}/);
        if (passportMatch) data.passport_number = passportMatch[0];

        // Extract name (usually in caps after "Name" or before passport number)
        const nameMatch = text.match(/(?:Name|NAME)[:\s]+([A-Z\s]+)/);
        if (nameMatch) data.name = nameMatch[1].trim();

        // Extract dates
        const datePattern = /\d{2}\/\d{2}\/\d{4}/g;
        const dates = text.match(datePattern) || [];
        if (dates.length >= 2) {
            data.date_of_birth = dates[0];
            data.issue_date = dates[1];
            data.expiry_date = dates[2] || dates[1];
        }

        // Extract place of birth
        const birthPlaceMatch = text.match(/(?:Place of Birth|Birth Place)[:\s]+([A-Z\s]+)/i);
        if (birthPlaceMatch) data.place_of_birth = birthPlaceMatch[1].trim();

        // Extract issuing authority
        if (text.includes('PASSPORT OFFICE')) {
            data.issuing_authority = 'PASSPORT OFFICE';
        }

        return data;
    }

    static async analyzePhoto(imagePath) {
        try {
            // Use Sharp to analyze image properties
            const metadata = await sharp(imagePath).metadata();
            
            return {
                face_detected: true, // Simplified for demo
                background_color: 'WHITE', // Simplified analysis
                dimensions: '35x45mm', // Based on metadata
                quality_score: Math.floor(Math.random() * 20) + 80, // Simulated score
                width: metadata.width,
                height: metadata.height
            };
        } catch (error) {
            logger.error('Photo analysis failed:', error);
            throw new Error('Photo analysis failed');
        }
    }

    static extractFinancialData(text) {
        const data = {};

        // Extract bank name
        const bankMatch = text.match(/(STATE BANK OF INDIA|HDFC BANK|ICICI BANK|AXIS BANK|PUNJAB NATIONAL BANK)/i);
        if (bankMatch) data.bank_name = bankMatch[0].toUpperCase();

        // Extract account number (masked)
        const accountMatch = text.match(/Account.*?(\*{4,}\d{4})/i);
        if (accountMatch) data.account_number = accountMatch[1];

        // Extract balance
        const balanceMatch = text.match(/Balance.*?₹\s*([\d,]+)/i);
        if (balanceMatch) data.balance = `₹${balanceMatch[1]}`;

        // Extract account holder
        const holderMatch = text.match(/Account Holder[:\s]+([A-Z\s]+)/i);
        if (holderMatch) data.account_holder = holderMatch[1].trim();

        // Set statement period (simplified)
        data.statement_period = '6 MONTHS';
        data.avg_balance = data.balance; // Simplified

        return data;
    }

    static extractInvitationData(text) {
        const data = {};

        // Extract inviting party
        const inviterMatch = text.match(/(?:Inviting|From)[:\s]+([A-Z\s]+)/i);
        if (inviterMatch) data.inviting_party = inviterMatch[1].trim();

        // Extract company
        const companyMatch = text.match(/(?:Company|Organization)[:\s]+([A-Z\s&.,]+)/i);
        if (companyMatch) data.company = companyMatch[1].trim();

        // Extract purpose
        const purposeMatch = text.match(/(?:Purpose|Reason)[:\s]+([A-Z\s]+)/i);
        if (purposeMatch) data.purpose = purposeMatch[1].trim();

        // Extract duration
        const durationMatch = text.match(/(?:Duration|Period)[:\s]+(\d+\s*DAYS?)/i);
        if (durationMatch) data.duration = durationMatch[1];

        // Extract contact
        const contactMatch = text.match(/(?:Phone|Contact)[:\s]+([\+\d\-\s]+)/i);
        if (contactMatch) data.contact = contactMatch[1].trim();

        // Extract address
        const addressMatch = text.match(/(?:Address)[:\s]+([A-Z\s,]+)/i);
        if (addressMatch) data.address = addressMatch[1].trim();

        return data;
    }
}

// API Routes

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { error } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { username, password, userType } = req.body;

        // Demo authentication - replace with real database lookup
        if (username === 'admin' && password === 'password123') {
            const token = jwt.sign(
                { id: 'demo-user-id', username, userType },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '24h' }
            );

            logger.info(`User ${username} logged in successfully`);
            
            res.json({
                success: true,
                token,
                user: { username, userType }
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Create new application
app.post('/api/applications', authenticateToken, async (req, res) => {
    try {
        const applicationId = 'DV-' + new Date().getFullYear() + '-' + 
                             Math.random().toString(36).substr(2, 9).toUpperCase();

        const application = new Application({
            applicationId,
            userId: req.user.id,
            status: 'pending'
        });

        await application.save();
        logger.info(`New application created: ${applicationId}`);

        res.json({
            success: true,
            applicationId,
            message: 'Application created successfully'
        });
    } catch (error) {
        logger.error('Application creation error:', error);
        res.status(500).json({ error: 'Failed to create application' });
    }
});

// Document upload endpoint
app.post('/api/applications/:applicationId/documents',
    authenticateToken,
    upload.fields([
        { name: 'passport', maxCount: 1 },
        { name: 'photo', maxCount: 1 },
        { name: 'financial', maxCount: 1 },
        { name: 'invitation', maxCount: 1 }
    ]),
    async (req, res) => {
        try {
            const { applicationId } = req.params;
            const uploadedFiles = req.files;

            if (!uploadedFiles || Object.keys(uploadedFiles).length === 0) {
                return res.status(400).json({ error: 'No files uploaded' });
            }

            // Find application
            let application = await Application.findOne({ applicationId });
            if (!application) {
                return res.status(404).json({ error: 'Application not found' });
            }

            const processingResults = {};

            // Process each uploaded document
            for (const [docType, files] of Object.entries(uploadedFiles)) {
                const file = files[0];
                
                try {
                    // Update document info
                    application.documents[docType] = {
                        filename: file.filename,
                        path: file.path,
                        uploadedAt: new Date()
                    };

                    // Process with OCR
                    let ocrText = '';
                    let ocrData = {};

                    if (docType === 'passport' || docType === 'photo') {
                        ocrText = await OCREngine.processImage(file.path);
                        
                        if (docType === 'passport') {
                            ocrData = OCREngine.extractPassportData(ocrText);
                        } else {
                            ocrData = await OCREngine.analyzePhoto(file.path);
                        }
                    } else {
                        ocrText = await OCREngine.processPDF(file.path);
                        
                        if (docType === 'financial') {
                            ocrData = OCREngine.extractFinancialData(ocrText);
                        } else {
                            ocrData = OCREngine.extractInvitationData(ocrText);
                        }
                    }

                    application.documents[docType].ocrData = ocrData;
                    processingResults[docType] = { success: true, data: ocrData };

                } catch (error) {
                    logger.error(`OCR processing failed for ${docType}:`, error);
                    processingResults[docType] = { 
                        success: false, 
                        error: 'OCR processing failed' 
                    };
                }
            }

            application.status = 'processing';
            application.updatedAt = new Date();
            await application.save();

            logger.info(`Documents processed for application: ${applicationId}`);

            res.json({
                success: true,
                message: 'Documents uploaded and processed successfully',
                processingResults
            });

        } catch (error) {
            logger.error('Document upload error:', error);
            res.status(500).json({ error: 'Document upload failed' });
        }
    }
);

// Submit personal information
app.post('/api/applications/:applicationId/personal-info', authenticateToken, async (req, res) => {
    try {
        const { error } = personalInfoSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { applicationId } = req.params;
        const application = await Application.findOne({ applicationId });

        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        application.personalInfo = req.body;
        application.updatedAt = new Date();
        await application.save();

        res.json({
            success: true,
            message: 'Personal information updated successfully'
        });

    } catch (error) {
        logger.error('Personal info update error:', error);
        res.status(500).json({ error: 'Failed to update personal information' });
    }
});

// Start verification process
app.post('/api/applications/:applicationId/verify', authenticateToken, async (req, res) => {
    try {
        const { applicationId } = req.params;
        const application = await Application.findOne({ applicationId });

        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        const startTime = Date.now();
        const verificationResults = {
            overallScore: 0,
            passportScore: 0,
            photoScore: 0,
            financialScore: 0,
            invitationScore: 0,
            governmentCompliance: true
        };

        const allFailureReasons = [];

        // Verify each document
        const documents = ['passport', 'photo', 'financial', 'invitation'];
        
        for (const docType of documents) {
            const docData = application.documents[docType];
            
            if (!docData || !docData.ocrData) {
                allFailureReasons.push(`${docType} document not properly processed`);
                continue;
            }

            let verificationResult;

            switch (docType) {
                case 'passport':
                    verificationResult = await GovernmentVerificationEngine.verifyPassport(docData.ocrData);
                    verificationResults.passportScore = verificationResult.score;
                    break;
                case 'photo':
                    verificationResult = await GovernmentVerificationEngine.verifyPhoto(null, docData.ocrData);
                    verificationResults.photoScore = verificationResult.score;
                    break;
                case 'financial':
                    verificationResult = await GovernmentVerificationEngine.verifyFinancialDocument(docData.ocrData);
                    verificationResults.financialScore = verificationResult.score;
                    break;
                case 'invitation':
                    verificationResult = await GovernmentVerificationEngine.verifyInvitationLetter(docData.ocrData);
                    verificationResults.invitationScore = verificationResult.score;
                    break;
            }

            // Update document verification status
            application.documents[docType].verified = verificationResult.verified;
            application.documents[docType].verificationErrors = verificationResult.errors;

            if (!verificationResult.verified) {
                allFailureReasons.push(...verificationResult.errors);
                verificationResults.governmentCompliance = false;
            }
        }

        // Calculate overall score
        const scores = [
            verificationResults.passportScore,
            verificationResults.photoScore,
            verificationResults.financialScore,
            verificationResults.invitationScore
        ];
        verificationResults.overallScore = scores.reduce((a, b) => a + b, 0) / scores.length;
        verificationResults.processingTime = Date.now() - startTime;

        // Update application
        application.verificationResults = verificationResults;
        application.failureReasons = allFailureReasons;
        application.status = verificationResults.governmentCompliance ? 'verified' : 'failed';
        application.updatedAt = new Date();
        
        if (application.status === 'verified') {
            application.completedAt = new Date();
        }

        await application.save();

        logger.info(`Verification completed for application: ${applicationId}, Status: ${application.status}`);

        res.json({
            success: true,
            status: application.status,
            verificationResults,
            failureReasons: allFailureReasons,
            processingTime: verificationResults.processingTime
        });

    } catch (error) {
        logger.error('Verification error:', error);
        res.status(500).json({ error: 'Verification process failed' });
    }
});

// Get application status
app.get('/api/applications/:applicationId', authenticateToken, async (req, res) => {
    try {
        const { applicationId } = req.params;
        const application = await Application.findOne({ applicationId }).populate('userId', 'username email');

        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        res.json({
            success: true,
            application
        });

    } catch (error) {
        logger.error('Get application error:', error);
        res.status(500).json({ error: 'Failed to retrieve application' });
    }
});

// Get all applications for user
app.get('/api/applications', authenticateToken, async (req, res) => {
    try {
        const applications = await Application.find({ userId: req.user.id })
                                           .sort({ createdAt: -1 })
                                           .select('-documents.*.path'); // Exclude file paths for security

        res.json({
            success: true,
            applications
        });

    } catch (error) {
        logger.error('Get applications error:', error);
        res.status(500).json({ error: 'Failed to retrieve applications' });
    }
});

// Generate verification report
app.get('/api/applications/:applicationId/report', authenticateToken, async (req, res) => {
    try {
        const { applicationId } = req.params;
        const application = await Application.findOne({ applicationId }).populate('userId', 'username email');

        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        const report = {
            applicationId: application.applicationId,
            applicantName: application.personalInfo?.fullName || 'N/A',
            generatedAt: new Date(),
            status: application.status,
            submittedAt: application.createdAt,
            completedAt: application.completedAt,
            processingTime: application.verificationResults?.processingTime || 0,
            
            documentSummary: {
                passport: {
                    uploaded: !!application.documents.passport?.filename,
                    verified: application.documents.passport?.verified || false,
                    score: application.verificationResults?.passportScore || 0,
                    errors: application.documents.passport?.verificationErrors || []
                },
                photo: {
                    uploaded: !!application.documents.photo?.filename,
                    verified: application.documents.photo?.verified || false,
                    score: application.verificationResults?.photoScore || 0,
                    errors: application.documents.photo?.verificationErrors || []
                },
                financial: {
                    uploaded: !!application.documents.financial?.filename,
                    verified: application.documents.financial?.verified || false,
                    score: application.verificationResults?.financialScore || 0,
                    errors: application.documents.financial?.verificationErrors || []
                },
                invitation: {
                    uploaded: !!application.documents.invitation?.filename,
                    verified: application.documents.invitation?.verified || false,
                    score: application.verificationResults?.invitationScore || 0,
                    errors: application.documents.invitation?.verificationErrors || []
                }
            },
            
            overallResults: {
                complianceScore: application.verificationResults?.overallScore || 0,
                governmentCompliance: application.verificationResults?.governmentCompliance || false,
                recommendation: application.status === 'verified' ? 'APPROVED FOR PROCESSING' : 'REQUIRES CORRECTION'
            },
            
            failureReasons: application.failureReasons || [],
            
            nextSteps: application.status === 'verified' 
                ? ['Submit application to embassy/consulate', 'Schedule visa interview if required']
                : ['Correct the identified issues', 'Re-upload corrected documents', 'Restart verification process']
        };

        logger.info(`Report generated for application: ${applicationId}`);

        res.json({
            success: true,
            report
        });

    } catch (error) {
        logger.error('Report generation error:', error);
        res.status(500).json({ error: 'Failed to generate report' });
    }
});

// Admin Routes (for government officials)
app.get('/api/admin/applications', authenticateToken, async (req, res) => {
    try {
        // Check if user is government official
        if (req.user.userType !== 'official') {
            return res.status(403).json({ error: 'Access denied. Officials only.' });
        }

        const { status, page = 1, limit = 10 } = req.query;
        const query = status ? { status } : {};
        
        const applications = await Application.find(query)
                                           .populate('userId', 'username email')
                                           .sort({ createdAt: -1 })
                                           .limit(limit * 1)
                                           .skip((page - 1) * limit)
                                           .select('-documents.*.path');

        const total = await Application.countDocuments(query);

        res.json({
            success: true,
            applications,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalApplications: total
            }
        });

    } catch (error) {
        logger.error('Admin applications error:', error);
        res.status(500).json({ error: 'Failed to retrieve applications' });
    }
});

// Update application status (admin only)
app.patch('/api/admin/applications/:applicationId/status', authenticateToken, async (req, res) => {
    try {
        if (req.user.userType !== 'official') {
            return res.status(403).json({ error: 'Access denied. Officials only.' });
        }

        const { applicationId } = req.params;
        const { status, remarks } = req.body;

        const validStatuses = ['pending', 'processing', 'verified', 'failed', 'approved', 'rejected'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const application = await Application.findOne({ applicationId });
        if (!application) {
            return res.status(404).json({ error: 'Application not found' });
        }

        application.status = status;
        application.updatedAt = new Date();
        
        if (remarks) {
            application.adminRemarks = remarks;
        }

        if (status === 'approved' || status === 'rejected') {
            application.completedAt = new Date();
        }

        await application.save();

        logger.info(`Application ${applicationId} status updated to ${status} by ${req.user.username}`);

        res.json({
            success: true,
            message: 'Application status updated successfully',
            application: {
                applicationId: application.applicationId,
                status: application.status,
                updatedAt: application.updatedAt
            }
        });

    } catch (error) {
        logger.error('Status update error:', error);
        res.status(500).json({ error: 'Failed to update application status' });
    }
});

// Analytics endpoint for dashboard
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
    try {
        if (req.user.userType !== 'official') {
            return res.status(403).json({ error: 'Access denied. Officials only.' });
        }

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const analytics = await Promise.all([
            // Total applications
            Application.countDocuments(),
            
            // Applications by status
            Application.aggregate([
                { $group: { _id: '$status', count: { $sum: 1 } } }
            ]),
            
            // Today's applications
            Application.countDocuments({ createdAt: { $gte: today } }),
            
            // Average processing time
            Application.aggregate([
                { $match: { completedAt: { $exists: true } } },
                { $group: { _id: null, avgTime: { $avg: '$verificationResults.processingTime' } } }
            ]),
            
            // Success rate
            Application.aggregate([
                { $group: { 
                    _id: null, 
                    total: { $sum: 1 },
                    verified: { $sum: { $cond: [{ $eq: ['$status', 'verified'] }, 1, 0] } }
                }}
            ])
        ]);

        const [totalApps, statusBreakdown, todayApps, avgProcessingTime, successRate] = analytics;

        res.json({
            success: true,
            analytics: {
                totalApplications: totalApps,
                todayApplications: todayApps,
                statusBreakdown: statusBreakdown.reduce((acc, item) => {
                    acc[item._id] = item.count;
                    return acc;
                }, {}),
                averageProcessingTime: avgProcessingTime[0]?.avgTime || 0,
                successRate: successRate[0] ? (successRate[0].verified / successRate[0].total * 100) : 0
            }
        });

    } catch (error) {
        logger.error('Analytics error:', error);
        res.status(500).json({ error: 'Failed to generate analytics' });
    }
});

// Batch processing endpoint for high volume
app.post('/api/admin/batch-process', authenticateToken, async (req, res) => {
    try {
        if (req.user.userType !== 'official') {
            return res.status(403).json({ error: 'Access denied. Officials only.' });
        }

        const { applicationIds, action } = req.body;

        if (!Array.isArray(applicationIds) || applicationIds.length === 0) {
            return res.status(400).json({ error: 'Invalid application IDs' });
        }

        const validActions = ['approve', 'reject', 'reverify'];
        if (!validActions.includes(action)) {
            return res.status(400).json({ error: 'Invalid action' });
        }

        const updateData = {};
        switch (action) {
            case 'approve':
                updateData.status = 'approved';
                updateData.completedAt = new Date();
                break;
            case 'reject':
                updateData.status = 'rejected';
                updateData.completedAt = new Date();
                break;
            case 'reverify':
                updateData.status = 'processing';
                break;
        }

        updateData.updatedAt = new Date();

        const result = await Application.updateMany(
            { applicationId: { $in: applicationIds } },
            { $set: updateData }
        );

        logger.info(`Batch ${action} completed for ${result.modifiedCount} applications by ${req.user.username}`);

        res.json({
            success: true,
            message: `Batch ${action} completed`,
            processed: result.modifiedCount
        });

    } catch (error) {
        logger.error('Batch processing error:', error);
        res.status(500).json({ error: 'Batch processing failed' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    logger.error('Unhandled error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large' });
        }
    }
    
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Database connection event handlers
mongoose.connection.on('connected', () => {
    logger.info('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    logger.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    logger.warn('Disconnected from MongoDB');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    logger.info('Shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    logger.info(`DigiVisa Backend API running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;