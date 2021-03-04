const crypto = require("crypto");
//const jwt = require("jsonwebtoken");

module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define("User", {
    id: {
      allowNull: false,
      primaryKey: true,
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4
    },
    fname: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notNull: { msg: "First name is required" },
        notEmpty: { msg: "First name is required" }
      }
    },
    lastname: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notNull: { msg: "Last name is required" },
        notEmpty: { msg: "Last name is required" }
      }
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: "composite",
      validate: {
        notNull: { msg: "Email is required" },
        notEmpty: { msg: "Email is required" },
        isEmail: { msg: "Must be a valid email address" }
      }
    },
    password: {
      type: DataTypes.STRING,
      get() {
        return () => this.getDataValue("password");
      }
    },
    salt: {
      type: DataTypes.STRING,
      get() {
        return () => this.getDataValue("salt");
      }
    },
    phoneNo: { type: DataTypes.STRING },
    orgId: {
      type: DataTypes.UUID,
      allowNull: true,
      unique: "composite"
    },
    tokens: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      defaultValue: []
    },
    role: {
      type: DataTypes.ENUM({
        values: ["admin", "user"]
      })
      //defaultValue: "user"
    },
    isEnabled: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    }
  });

  /*   const payload = {
    id: this.id,
    role: this.role,
    time: new Date(),
  };

  User.generateToken = async function() {
    const user = this;
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: '12h'
    });

    return token;
  }; */

  User.generateSalt = function() {
    return crypto.randomBytes(16).toString("base64");
  };

  User.encryptPassword = function(plainText, salt) {
    return crypto
      .createHash("RSA-SHA256")
      .update(plainText)
      .update(salt)
      .digest("hex");
  };

  // User.generateKey = function() {
  //   const apiKey = crypto.randomBytes(25).toString("base64");

  //   this.api_key = crypto
  //     .createHash("sha256")
  //     .update(apiKey)
  //     .digest("hex");
  //   return apiKey;
  // };

  const setSaltAndPassword = user => {
    if (user.changed("password")) {
      user.salt = User.generateSalt();
      user.password = User.encryptPassword(user.password(), user.salt());
    }
    // if (user.role === "user") {
    //   user.salt = null;
    //   user.password = null;
    // }
  };
  // const setApiKey = user => {
  //   user.access_key_id = User.generateKey();
  //   user.secret_key = User.generateKey();
  // };

  User.beforeCreate(user => {
    if (!user.createdBy) {
      // eslint-disable-next-line no-param-reassign
      user.createdBy = user.id;
    }
    // eslint-disable-next-line no-param-reassign
    user.email = user.email.toLowerCase();
  });
  User.beforeCreate(setSaltAndPassword);
  // User.beforeCreate(setApiKey);
  User.beforeUpdate(setSaltAndPassword);

  User.prototype.correctPassword = function(enteredPassword) {
    return (
      User.encryptPassword(enteredPassword, this.salt()) === this.password()
    );
  };

  User.associate = function(models) {
    // association can be defined here
    User.hasMany(models.products, {
      foreignKey: "userId"
    });
    User.hasMany(models.apps, {
      foreignKey: "userId"
    });
    User.hasMany(models.modules, {
      foreignKey: "userId"
    });
    User.hasMany(models.userintegrations, {
      foreignKey: "userId"
    });
    User.hasMany(models.subusers, {
      foreignKey: "userId",
      as: "subuser"
    });
  };
  return User;
};