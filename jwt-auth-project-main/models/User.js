const mongoose = require('mongoose')
const { isEmail } = require('validator')
const bcrypt = require('bcrypt')

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Please enter email'],
        unique: true,
        lowercase: true,
        validate: [isEmail, "Please enter valid email"]
    },
    password: {
        type: String,
        required: [true, 'Please enter password'],
        minlength: [6, 'Password should be minimum 6 characters long']
    }
})

// fires a mongoose hook before saving document in the db using pre()

userSchema.pre('save', async function (next) {
    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt)
    next();
})

userSchema.statics.login = async function (email, password) {

    const user = await this.findOne({ email })
    if (user) {
        const auth = await bcrypt.compare(password, user.password)
        if (auth) {
            return user
        }
        throw Error("Incorrect Password(user.js)")
    }
    throw Error("Incorrect Email(user.js)")

}
const User = mongoose.model('coljwt', userSchema)
module.exports = User