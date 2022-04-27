/**
 * Module for the UsersController.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

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

      const accessToken = jwt.sign(payload, Buffer.from(process.env.PRIVATE_KEY, 'base64').toString('ascii'), {
        algorithm: 'RS256',
        expiresIn: process.env.PRIVATE_KEY_LIFE
      })

      const randomToken = crypto.randomBytes(256).toString('hex')

      const refreshToken = new RefreshToken({
        userId: user.id,
        refreshToken: randomToken
      })

      await refreshToken.save()

      res
        .status(201)
        .json({
          access_token: accessToken,
          refresh_token: randomToken
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

      await user.save()

      res
        .status(201)
        .json({ id: user.id })
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
}
