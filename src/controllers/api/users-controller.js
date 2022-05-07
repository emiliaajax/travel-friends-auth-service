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

      const accessToken = this.genereateJWT(payload)

      const refreshToken = this.generateRefreshToken(user.id)

      res
        .status(201)
        .json({
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

      console.log(user.id)

      const response = await fetch(process.env.USER_PROFILES_SERVICE, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
          // 'X-API-Private-Token': process.env.PERSONAL_ACCESS_TOKEN
        },
        body: JSON.stringify({
          userId: user.id
        })
      })

      const data = await response.json()

      const payload = {
        sub: user.id
      }

      const accessToken = await this.genereateJWT(payload)

      const refreshToken = await this.generateRefreshToken(user.id)

      await user.save()

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
   * Generates a jwt.
   *
   * @param {object} payload dasd.
   * @returns {string} A jwt.
   */
  async genereateJWT (payload) {
    return jwt.sign(payload, Buffer.from(process.env.PRIVATE_KEY, 'base64').toString('ascii'), {
      algorithm: 'RS256',
      expiresIn: process.env.PRIVATE_KEY_LIFE
    })
  }

  /**
   * Generates a refresh token.
   *
   * @param {string} id The id of the user.
   * @returns {string} The generated refresh token.
   */
  async generateRefreshToken (id) {
    const randomToken = crypto.randomBytes(256).toString('hex')

    const refreshToken = new RefreshToken({
      userId: id,
      refreshToken: randomToken
    })

    await refreshToken.save()

    return randomToken
  }
}
