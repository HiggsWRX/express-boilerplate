const express = require('express')
const router = express.Router()
const httpStatus = require('http-status')
const { check, validationResult } = require('express-validator')
const jwt = require('jsonwebtoken')

const User = require('../../models/User')
const authController = require('../../controllers/auth.controller')
const auth = require('../../middlewares/authorization')
const config = require('../../config')

router.post(
  '/register',
  [
    check('name').not().isEmpty().withMessage('Name is required'),
    check('email').isEmail().withMessage('Please include a valid email'),
    check('password').isLength({min: 9}).withMessage('Password must have 9 or more characters')
  ],
  async (req, res, next) => {
    try {
      const validationErrors = validationResult(req)

      if (!validationErrors.isEmpty()) {
        return res.status(400).json({ errors: validationErrors.array() })
      }

      const user = new User(req.body)
      await user.save()

      const payload = {
        user: {
          id: user.id
        }
      }

      const token = jwt.sign(payload, config.secret)

      res.status(httpStatus.CREATED)
      res.json({ message: 'OK', token: token })
    } catch (error) {
      return next(User.checkDuplicateEmailError(error))
    }
  }
)

router.post('/login', authController.login) // login
router.get('/confirm', authController.confirm)

// Authentication example
router.get('/secret1', auth(), (req, res) => {
  // example route for auth
  res.json({ message: 'Anyone can access(only authorized)' })
})
router.get('/secret2', auth(['admin']), (req, res) => {
  // example route for auth
  res.json({ message: 'Only admin can access' })
})
router.get('/secret3', auth(['user']), (req, res) => {
  // example route for auth
  res.json({ message: 'Only user can access' })
})

module.exports = router
