/**
 * Mongoose model User.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import validator from 'validator'

const schema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    validate: [validator.isEmail, 'Ange en giltig e-mail']
  },
  password: {
    type: String,
    required: true,
    minlength: [10, 'Lösenordet måste vara minst 10 tecken'],
    maxlength: [1000, 'Lösenordet måste vara mindre än 256 tecken']
  },
  profileId: {
    type: String
  }
}, {
  timestamps: true,
  toJSON: {
    /**
     * Removes sensitive information by transforming the resulting object.
     *
     * @param {object} doc The mongoose document to be converted.
     * @param {object} ret The plain object response which has been converted.
     */
    transform: function (doc, ret) {
      delete ret._id
      delete ret.__v
    }
  },
  virtuals: true
})

schema.virtual('id').get(function () {
  return this._id.toHexString()
})

/**
 * Authenticates an account.
 *
 * @param {string} email The email.
 * @param {string} password The password.
 * @returns {Promise} Resolves to a user object.
 */
schema.statics.authenticate = async function (email, password) {
  const user = await this.findOne({ email })
  if (!user || !(await bcrypt.compare(password, user.password))) {
    throw new Error('Credentials invalid or not provided.')
  }
  return user
}

// Creates a model using the schema.
export const User = mongoose.model('User', schema)
