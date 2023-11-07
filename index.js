const express = require('express')
const app = express()
const { User, Token } = require('./app/models')
const bcrypt = require('bcrypt')
const randomString = require('randomstring')

app.use(express.json())

const tokenAuth = async (req, res, next) => {
  const authorizationToken = req.headers['authorization']
  if (!authorizationToken) {
    res.status(401).send({ error: 'No token provided' })
    return
  }
  const userToken = await Token.findOne({ where: { token: authorizationToken } })
  if (!userToken) {
    res.status(401).send({ error: 'Invalid token' })
    return
  }
  const user = await User.findByPk(userToken.userId)
  req.user = user.toJSON()

  next()
}

app.post('/', async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({
    where: { email: email }
  })

  if (!user) {
    res.status(422).send({ error: 'Invalid credentials' })
    return
  }

  const validPassword = await bcrypt.compare(password, user.password)
  if (!validPassword) {
    res.status(422).send({ error: 'Invalid credentials' })
    return
  }

  const token = randomString.generate()
  await Token.create({ userId: user.id, token: token })
  res.json({ token: token })
})

app.get('/protected', tokenAuth, async (req, res) => {
  res.json({
    message: 'This is a protected route'
  })
})

app.listen(3000, () => {
  console.log('Server is running on port 3000')
})
