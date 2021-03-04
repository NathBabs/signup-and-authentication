const jwt = require("jsonwebtoken");
const User = require("../models/user");
const {
  Sequelize,
  Model
} = require('sequelize');


const generateAuthToken = async (instance) => {
  const token = jwt.sign({
    id: instance.id.toString(),
    role: instance.role
  }, process.env.JWT_SECRET, {
    expiresIn: '45m'
  });

  instance.tokens = instance.tokens.concat(token);

  await instance.save();

  return token;
};

module.exports = generateAuthToken;
