'use strict'

const { User } = require('../../app/models')
const { faker } = require('@faker-js/faker')

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    for (let i = 0; i < 10; i++) {
      await User.create({
        name: 'John ' + i,
        email: 'email-' + i + '@gmail.com',
        password: 'password'
      })
    }
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.bulkDelete('Tokens', null, {})
    await queryInterface.bulkDelete('Users', null, {})
  }
}
