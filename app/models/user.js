'use strict'
const { Model } = require('sequelize')
const bcrypt = require('bcrypt')
const auth = require('../../config/auth')

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  User.init(
    {
      name: DataTypes.STRING,
      email: DataTypes.STRING,
      password: DataTypes.STRING
    },
    {
      sequelize,
      modelName: 'User'
    }
  )

  User.beforeCreate(async (user, options) => {
    try {
      const hash = await bcrypt.hash(user.password, auth.bcryptRound)
      user.password = hash
    } catch (err) {
      throw new Error()
    }
  })
  return User
}
