/**
 * Module for the AccountController.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import jwt from 'jsonwebtoken'
import { User } from '../../models/user.js'
import createError from 'http-errors'

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
      const user = await User.authenticate(req.body.username, req.body.password)

      const payload = {
        sub: user.id,
        username: user.username,
        given_name: user.firstName,
        family_name: user.lastName,
        email: user.email
      }

      const accessToken = jwt.sign(payload, Buffer.from(process.env.PRIVATE_KEY_SECRET, 'base64').toString('ascii'), {
        algorithm: 'RS256',
        expiresIn: process.env.PRIVATE_KEY_LIFE
      })

      res
        .status(201)
        .json({
          access_token: accessToken
        })
    } catch (error) {
      const err = createError(401)
      err.cause = error
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
        username: req.body.username,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email
      })

      await user.save()

      res
        .status(201)
        .json({ id: user.id })
    } catch (error) {
      let err = error

      if (err.code === 11000) {
        // Duplicated keys
        err = createError(409)
        err.cause = error
      } else if (error.name === 'ValidationError') {
        err = createError(400)
        err.cause = error
        err.message = 'The request cannot or will not be processed due to something that is perceived to be a client error (for example validation error).'
      }

      next(err)
    }
  }
}
