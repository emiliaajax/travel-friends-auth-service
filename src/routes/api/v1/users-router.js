/**
 * Users routes.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import express from 'express'
import { UsersController } from '../../../controllers/api/users-controller.js'

export const router = express.Router()

const controller = new UsersController()

router.post('/login', (req, res, next) => controller.login(req, res, next))

router.post('/register', (req, res, next) => controller.register(req, res, next))

router.post('/logout', (req, res, next) => controller.logout(req, res, next))
