const jwt = require('jsonwebtoken')
const { signupSchema } = require("../middlewares/validator")
const { signinSchema } = require("../middlewares/validator")
const User = require('../models/usersModel')
const { doHash, doHashValidation } = require('../utils/hashing')

exports.signup = async (req, res) => {
    const { email, password } = req.body;
    try {
        const { error, value } = signupSchema.validate({ email, password })

        if (error) {
            return res
                .status(401)
                .json({ sucess: false, message: error.details[0].message })
        }
        const existingUser = await User.findOne({ email })

        if (existingUser) {
            return res
                .status(401)
                .json({ sucess: false, message: "User already exist!" })
        }

        const hashedPassword = await doHash(password, 12)

        const newUser = new User({
            email,
            password: hashedPassword
        })
        const result = await newUser.save();
        result.password = undefined;
        res.status(201).json({
            success: true,
            message: "Your account has been created successfully",
            result,
        })

    } catch (error) {
        console.log(error)
    }
};

exports.signin = async (req, res) => {
    const { email, password } = req.body;
    try {
        const { error, value } = signinSchema.validate({ email, password });
        if (error) {
            return res
                .status(401)
                .json({ sucess: false, message: error.details[0].message })
        }

        const existingUser = await User.findOne({ email }).select('+password')
        if (!existingUser) {
            return res
                .status(401)
                .json({ sucess: false, message: "User exist does not exist!" })
        }
        const result = await doHashValidation(password, existingUser.password)
        if (!result) {
            return res
                .status(401)
                .json({ success: false, message: 'Invalid credentials' })
        }
        const token = jwt.sign({
            userid: existingUser._id,
            email: existingUser.email,
            verified: existingUser.verified
        },
            process.env.TOKEN_SECRET
        );

        res.cookie('Authorization', 'Bearer' + token, {
            expires: new Date(Date.now() + 8
                * 3600000),
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NOD_ENV === 'production'
        })
            .json({
                success: true,
                token,
                message: 'logged in successfully'
            })
    } catch (error) {
        console.log(error)
    }
};

exports.signout = async (req, res) => {
    res
        .clearCookies('Authorization')
        .status(200)
        .json({ success: true, message: 'logged out successfully' })
};