const mongoose = require('mongoose');

const postSchema = mongoose.Schema({
    title: {
    },
    description: {
        type: String,
        required: [true, 'descrption is required'],
        trim: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    }
}, { timestamps: true })

module.exports = mongoose.model('Post', postSchema)