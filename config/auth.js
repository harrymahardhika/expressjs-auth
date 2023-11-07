require('dotenv').config()

module.exports = {
  bcryptRound: parseInt(process.env.BCRYPT_ROUND),
  key: process.env.APP_KEY
}
