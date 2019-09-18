const express = require('express')
const router = express.Router()
const authRouter = require('./auth.route')
const usersRouter = require('./users.route')

router.get('/status', (req, res) => { res.send({status: 'OK'}) }) // api status

router.use('/auth', authRouter) // mount auth paths
router.use('/users', usersRouter) // mount users paths

module.exports = router
