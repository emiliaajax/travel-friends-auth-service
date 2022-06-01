/**
 * Module for the UsersController.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import fetch from 'node-fetch'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import { User } from '../../models/user.js'
import createError from 'http-errors'
import crypto from 'crypto'
import { RefreshToken } from '../../models/refresh-token.js'

/**
 * Encapsulates a controller.
 */
export class UsersController {
  /**
   * Authenticates a user.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async login (req, res, next) {
    try {
      const user = await User.authenticate(req.body.email, req.body.password)

      const payload = {
        sub: user.id
      }

      const accessToken = this.generateAccessToken(payload)
      const refreshToken = this.generateRefreshToken()

      const token = new RefreshToken({
        userId: user.id,
        refreshToken
      })

      await token.save()

      res
        .status(201)
        .json({
          id: user.id,
          profileId: user.profileId,
          accessToken,
          refreshToken
        })
    } catch (error) {
      const err = createError(401)
      err.cause = error
      err.message = 'E-mail eller lösenord är inkorrekt'
      next(err)
    }
  }

  /**
   * Logging out a user.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async logout (req, res, next) {
    try {
      await RefreshToken.deleteOne({ userId: req.body.id })
      res
        .status(204)
        .end()
    } catch (error) {
      next(error)
    }
  }

  /**
   * Registers a user.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async register (req, res, next) {
    try {
      if (req.body.password.length < 10) {
        const err = createError(400)
        err.message = 'Lösenordet måste vara minst 10 tecken'
        return next(err)
      }

      if (req.body.password.length > 1000) {
        const err = createError(400)
        err.message = 'Lösenordet måste vara mindre än 1000 tecken'
        return next(err)
      }

      const user = new User({
        email: req.body.email,
        password: req.body.password
      })

      const profile = {
        userId: user.id
      }

      const response = await fetch(process.env.USER_PROFILES_SERVICE, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(profile)
      })

      const data = await response.json()

      user.profileId = data.id

      user.password = await bcrypt.hash(user.password, 10)

      await user.save()

      const payload = {
        sub: user.id
      }

      const accessToken = this.generateAccessToken(payload)
      const refreshToken = this.generateRefreshToken()

      const token = new RefreshToken({
        userId: user.id,
        refreshToken
      })

      await token.save()

      res
        .status(201)
        .json({
          id: user.id,
          profileId: data.id,
          accessToken,
          refreshToken
        })
    } catch (error) {
      let err = error
      if (err.code === 11000) {
        err = createError(409)
        err.message = 'E-mail används redan'
      } else if (error.name === 'ValidationError') {
        err = createError(400)
      }

      next(err)
    }
  }

  /**
   * Finds user account.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async find (req, res, next) {
    try {
      const user = await User.findById(req.user.id)
      if (!user) {
        return next(createError(404))
      }

      res
        .status(201)
        .json(user.email)
    } catch (error) {
      next(error)
    }
  }

  /**
   * Changes email.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async changeEmail (req, res, next) {
    try {
      const user = await User.findById(req.user.id)

      if (!user) {
        return next(createError(404))
      }

      user.email = req.body.email

      await user.save()

      res
        .status(201)
        .json(user.email)
    } catch (error) {
      let err = error
      if (err.code === 11000) {
        err = createError(409)
        err.message = 'E-mail används redan'
      } else if (error.name === 'ValidationError') {
        err = createError(400)
      }

      next(err)
    }
  }

  /**
   * Changes the password.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async changePassword (req, res, next) {
    try {
      if (req.body.newPassword.length < 10) {
        const err = createError(400)
        err.message = 'Lösenordet måste vara minst 10 tecken'
        return next(err)
      }

      if (req.body.newPassword.length > 1000) {
        const err = createError(400)
        err.message = 'Lösenordet måste vara mindre än 1000 tecken'
        return next(err)
      }

      const user = await User.findById(req.user.id)

      await User.authenticate(user.email, req.body.currentPassword)

      user.password = await bcrypt.hash(req.body.newPassword, 10)

      await user.save()

      const token = await RefreshToken.findOne({ userId: req.user.id })

      const payload = {
        sub: user.id
      }

      const newAccessToken = this.generateAccessToken(payload)
      const newRefreshToken = this.generateRefreshToken()

      token.refreshToken = newRefreshToken

      await token.save()

      res
        .status(201)
        .json({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken
        })
    } catch (error) {
      const err = createError(401)
      err.cause = error
      err.message = 'Lösenord är inkorrekt'
      next(err)
    }
  }

  /**
   * Deletes account.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async delete (req, res, next) {
    try {
      const user = await User.findById(req.user.id)

      await User.authenticate(user.email, req.body.password)

      await fetch(process.env.USER_PROFILES_SERVICE + `${user.profileId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: req.headers.authorization
        }
      })

      await user.deleteOne()

      res
        .status(204)
        .end()
    } catch (error) {
      const err = createError(401)
      err.cause = error
      err.message = 'Lösenord är inkorrekt'
      next(err)
    }
  }

  /**
   * Check if authenticated.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async checkIfValid (req, res, next) {
    try {
      const token = await RefreshToken.findOne({ userId: req.body.id, refreshToken: req.body.refreshToken })

      if (!token) {
        return next(createError(401))
      }

      const payload = {
        sub: token.userId
      }

      const newAccessToken = this.generateAccessToken(payload)
      const newRefreshToken = this.generateRefreshToken()

      token.refreshToken = newRefreshToken

      await token.save()

      res
        .status(201)
        .json({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken
        })
    } catch (error) {
      next(error)
    }
  }

  /**
   * Generates a jwt.
   *
   * @param {object} payload dasd.
   * @returns {string} A jwt.
   */
  generateAccessToken (payload) {
    return jwt.sign(payload, Buffer.from(process.env.PRIVATE_KEY, 'base64').toString('ascii'), {
      algorithm: 'RS256',
      expiresIn: process.env.PRIVATE_KEY_LIFE
    })
  }

  /**
   * Generates a refresh token.
   *
   * @returns {string} The generated refresh token.
   */
  generateRefreshToken () {
    return crypto.randomBytes(256).toString('hex')
  }
}
