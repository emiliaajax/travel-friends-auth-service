/**
 * Module for the UsersController.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import fetch from 'node-fetch'
import jwt from 'jsonwebtoken'
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
      err.message = 'E-mail or password are incorrect.'
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
          // 'X-API-Private-Token': process.env.PERSONAL_ACCESS_TOKEN
        },
        body: JSON.stringify(profile)
      })

      const data = await response.json()

      user.profileId = data.id

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
        err.cause = error
        err.message = 'E-mail is already in use.'
      } else if (error.name === 'ValidationError') {
        err = createError(400)
        err.cause = error
        err.message = 'The request cannot or will not be processed due to something that is perceived to be a client error.'
      }

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
