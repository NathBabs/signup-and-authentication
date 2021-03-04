const { Op, DataTypes } = require("sequelize");
const jwt = require("jsonwebtoken");
const sequelize = require("../config/database/connection");
//const User = require('../models/user');
const User = require("../models/user")(sequelize, DataTypes);

const auth = async (req, res, next) => {
  try {
    //validate the token , from the header
    const token = req.header("Authorization").replace("Bearer ", "");

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    //console.log(`This is ${decoded.id}`);

    const user = await User.findOne({
      where: {
      id: decoded.id,
      role: decoded.role,
      tokens: {
        [Op.contains]: [token]
      }
    }
  });

    if (!user) {
      throw new Error();
    }

    // a missing logic is to detect the token expiration error
    // then delete that particular token from the array of tokens in
    // user table

    //since this method has already found the user, there's no need for the route handler to start finding the user again.
    req.token = token;
    req.user = user;
    req.user.role = decoded.role;
    next();
    //console.log(token);
  } catch (error) {
    //console.log(e);
    return res.status(401).send({
      message: "Please authenticate",
      error: error
    });
  }
};

module.exports = auth;
