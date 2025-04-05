const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors')
const dotenv = require('dotenv')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer')
const crypto = require('crypto')

const app = express();

app.use(cors());
app.use(express.json());

dotenv.config()

const PORT = process.env.PORT || 4000

// DB Connection

const DBConnection = () => {
    try {
        mongoose.connect(process.env.DB_URL);
        console.log(`database connected successfully`)
    } catch (error) {
        console.error('problem while connecting DB');
    }
}
DBConnection()

// schemas

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    resetToken: String,
    resetTokenExpiry: Date
})

const User = mongoose.model("User", userSchema)

// create token
const createToken = (user) => {
    return jwt.sign({id: user._id}, process.env.JWT_SECRET_KEY, {
        expiresIn: process.env.JWT_EXPIRE_IN || '1d'
    });
}

// nodemailer
const sendEmail = async (to, subject,html) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    })
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to,
        subject,
        html
    });
};

// signup
app.post(`/signup`, async(req, res) => {
    const {firstName, lastName, email, password} = req.body;
    try {
        const exists = await User.findOne({email});
        if(exists) {
            return res.status(400).json({message:'email already exists'});
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const newUser = User({
            firstName,
            lastName,
            email,
            password: hashedPassword
        })
        await newUser.save();
        res.status(200).json({message:`User register successfully`});
    } catch (error) {
        res.status(500).json({message:'error while registering user'});
    }
})

// login
app.post(`/login`, async(req, res) => {
    const {email, password} = req.body;
    try {
        const user = await User.findOne({email})
        if(!user) {
            return res.status(400).json({message:'Invalid user not found'})
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) return res.status(400).json({message:"password does not match"})

        const token = createToken(user);
        res.status(200).json({message:"login successful",
            token,
            user: {id: user._id, email: user.email}
        })
    } catch (error) {
        res.status(500).json({message:"error while login"});
    }
})

// forgot password
app.post('/forgot-password', async(req, res) => {
    const {email} = req.body;
    try {
        const user = await User.findOne({email});
        if(!user) return res.status(400).json({message:"No user found with email"})
        
        const token = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex')
        user.resetToken = hashedToken;
        user.resetTokenExpiry = Date.now() + 5 * 60 * 1000
        await user.save();
        const resetURL = `http://localhost:5000/reset-password/${token}`;
        const html = `<p> Click the link to reset your password: </p><a href="${resetURL}">${resetURL}</a>`;

        await sendEmail(user.email, `Reset your password`, html);

        res.status(200).json({
            message:"Reset token generated",
            resetURL,
            token: token
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({message:'error while forgetting password'});
    }
})

// reset password
app.post(`/reset-password/:token`, async(req, res) => {
    const hashedToken = crypto.createHash(`sha256`).update(req.params.token).digest('hex');
    try {
        const user = await User.findOne({
            resetToken: hashedToken,
            resetTokenExpiry: { $gt: Date.now()}
        })
        if(!user) return res.status(400).json({message:'Token is invalid or expired'})

        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        user.password = hashedPassword;
        user.resetToken = undefined,
        user.resetTokenExpiry = undefined
        await user.save();

        res.status(200).json({message: 'Password Updated successfully'})

    } catch (error) {
        res.status(500).json({message:'error while updating password'});
    }
})

app.get('/', (req, res) => {
    res.send("Hello")
})


app.listen(PORT, () => {
    console.log(`sever is listening on ${PORT}`)
})