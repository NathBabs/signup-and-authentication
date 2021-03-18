const {
  Op,
  DataTypes
} = require("sequelize");
const sequelize = require("../config/database/connection");
const User = require("../models/user")(sequelize, DataTypes);
const generateAuthToken = require("../helpers/generateAuthToken");

const jwt = require("jsonwebtoken");
const axios = require("axios").default;

exports.addNewUser = async (req, res, next) => {
  try {
    /* const ac = await Permission();
    const permission = await ac.can(req.body.role).execute('create').on('Notification'); */
    delete req.body.role;

    const payload = {
      // eslint-disable-next-line node/no-unsupported-features/es-syntax
      ...req.body,
      role: "admin"
    };

    const user = await User.create(payload);
    const token = await generateAuthToken(user);

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "User could not be created"
      });
    }

    return res.status(201).send({
      success: true,
      message: "User created",
      payload: {
        user: user,
        token: token
      }
    });
  } catch (error) {
    next(error);
  }
};

// login
exports.login = async (req, res, next) => {
  try {
    const user = await User.findOne({
      where: {
        email: req.body.email
      }
    });

    if (!user) {
      return res.status(401).send({
        success: false,
        message: "Wrong username or password"
      });
    }

    const correct = await user.correctPassword(req.body.password);

    if (!correct) {
      return res.status(401).send({
        success: false,
        message: "Wrong username or password"
      });
    }
    const token = await generateAuthToken(user);

    return res.status(200).send({
      success: true,
      message: "successfully logged in",
      payload: {
        user: user,
        token: token
      }
    });
  } catch (error) {
    return res.status(400).send();
  }
};

exports.currentUser = async (req, res, next) => {
  try {
    const {
      user
    } = req;

    return res.status(200).send({
      success: true,
      data: {
        user: user
      }
    });
  } catch (error) {
    return res.status(404).send(error);
  }
};

exports.logoutUser = async (req, res, next) => {
  try {
    //return a filtered token array that doesn't contain the current token being returned from the auth.js file
    req.user.tokens = req.user.tokens.filter(token => {
      return token != req.token;
    });
    //save the modified user, that the current token has been removed
    await req.user.save();

    return res.status(204).send({
      success: true
    });
  } catch (error) {
    res.status(500).send();
  }
};

exports.logoutAll = async (req, res, next) => {
  try {
    req.user.tokens = [];
    await req.user.save();
    return res.send();
  } catch (e) {
    res.status(500).send();
  }
};

exports.updateUser = async (req, res, next) => {
  const updates = Object.keys(req.body);
  const allowedUpdates = [
    "fname",
    "lastname",
    "email",
    "phoneNo"
  ];

  const isValidOperation = updates.every(update => {
    return allowedUpdates.includes(update);
  });

  if (!isValidOperation) {
    return res.status(400).send({
      success: false,
      message: "Invalid update"
    });
  }

  try {
    const user = await User.update({
      ...req.body
    }, {
      where: {
        id: req.params.id
      }
    });

    return res.status(200).send({
      success: true,
      user
    });
  } catch (error) {
    next(error);
  }
};

exports.findUserbyId = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "User not found"
      });
    }

    return res.status(200).send({
      success: true,
      user: user
    });
  } catch (error) {
    next(error);
  }
};


exports.sendResetLink = async (req, res, next) => {
  try {
    const email = req.body.email;

    const user = await User.findOne({
      where: {
        email: email
      }
    });

    if (!user) {
      return res.status.status(404).send({
        success: false,
        message: "This user doesn't exist"
      });
    }

    const token = jwt.sign({
      id: user.id.toString(),
      role: user.role
    }, process.env.JWT_SECRET, {
      expiresIn: '15m'
    });

    const link = `http://localhost:8080/api/v1/reset_password/${token}`;
    // use your own email api client, mine is different
    // you can use sendgrid or mailgun
    const emailData = {
      "namespace": "OnerunnerEmailVerification",
      "data": [{
        "email": `${user.email}`,
        "from": "support@company.com",
        "fromName": "Company support",
        "replyTo": "noreply@company.com",
        "replyToName": " Support",
        "subject": "Password Reset link",
        "name": `${link}`,
        //"verificationCode": "7779597"
      }]
    };

    const sentMail = await axios.post(`${process.env.MAIL_URL}/api/mail/send`, emailData);
    //console.log(sentMail);

    return res.status(200).send({
      success: true,
      message: "Email sent, please check your email",
      data: sentMail.data
    });

  } catch (error) {
    return res.status(500).send(error);
  }
};

exports.resetPassword = async (req, res, next) => {
  try {
    const token = req.params.token;
    const {
      password
    } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const updatedUser = await User.update({
      password: password
    }, {
      where: {
        id: decoded.id,
        role: decoded.role
      },
      individualHooks: true
    });

    return res.status(200).send({
      success: true,
      message: "Password changed succesfully",
      user: updatedUser
    });
  } catch (error) {
    return res.status(500).send(error);
  }
};
