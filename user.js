let mongoose = require('mongoose')
let crypto = require('crypto')

let userSchema = mongoose.Schema({
    email: String,
    password: String
})


module.exports = mongoose.model('User', userSchema)
