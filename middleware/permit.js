// middleware for doing role-based permissions
const permit = (...permittedRoles) => {
    // return a middleware
    return (req, res, next) => {
      const { user } = req;
  
      if (user && permittedRoles.includes(user.role)) {
        next(); // role is allowed, so continue on the next middleware
      } else {
        res.status(403).json({message: "Forbidden"}); // user is forbidden
      }
    };
  };

module.exports = permit;

