const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true
    },
    password: String
});

userSchema.pre('save', function(next) {
    const user = this;

    // generate a salt - it takes some amount of time thus the callback function.
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return next(err);
        }

        // has (encript) our password using the salt.
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) {
                return next(err);
            }

            // overwrite plain text password with hashed password.
            user.password = hash;
            next();
        })
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) {
            return callback(err);
        }

        callback(null, isMatch);
    });
}

const ModelClass = mongoose.model('user', userSchema);

module.exports = ModelClass;