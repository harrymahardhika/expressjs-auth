require('dotenv').config()

const host = process.env.DB_HOST
const database = process.env.DB_DATABASE
const username = process.env.DB_USERNAME
const password = process.env.DB_PASSWORD

module.exports = {
  development: {
    username: username,
    password: password,
    database: database,
    host: host,
    dialect: 'mysql'
  },
  test: {
    username: username,
    password: password,
    database: database,
    host: host,
    dialect: 'mysql'
  },
  production: {
    username: username,
    password: password,
    database: database,
    host: host,
    dialect: 'mysql'
  }
}
