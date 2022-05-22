/**
 * Users routes.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import express from 'express'
import jwt from 'jsonwebtoken'
import createError from 'http-errors'
import { UsersController } from '../../../controllers/api/users-controller.js'

export const router = express.Router()

const controller = new UsersController()

/**
 * Authenticates the request.
 *
 * @param {object} req Express request object.
 * @param {object} res Express response object.
 * @param {Function} next Express next middleware function.
 */
const authenticateJWT = (req, res, next) => {
  try {
    const [authenticationScheme, token] = req.headers.authorization?.split(' ')

    if (authenticationScheme !== 'Bearer') {
      throw new Error('Invalid authentication scheme')
    }

    const payload = jwt.verify(token, Buffer.from(process.env.PRIVATE_KEY, 'base64').toString('ascii'),
      {
        algorithms: 'RS256'
      })

    req.user = {
      id: payload.sub
    }

    next()
  } catch (error) {
    const err = createError(401)
    err.message = 'Access token invalid or not provided.'
    err.cause = error
    next(err)
  }
}

router.post('/login', (req, res, next) => controller.login(req, res, next))

router.post('/register', (req, res, next) => controller.register(req, res, next))

router.post('/logout', (req, res, next) => controller.logout(req, res, next))

router.post('/token', (req, res, next) => controller.checkIfValid(req, res, next))

router.get('/account',
  authenticateJWT,
  (req, res, next) => controller.find(req, res, next)
)

router.patch('/change-email',
  authenticateJWT,
  (req, res, next) => controller.changeEmail(req, res, next)
)

router.patch('/change-password',
  authenticateJWT,
  (req, res, next) => controller.changePassword(req, res, next)
)

router.delete('/delete',
  authenticateJWT,
  (req, res, next) => controller.delete(req, res, next)
)
