const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Users = require('../users/users-model.js');
const { validateUser } = require('../users/users-helpers');

router.post('/register', (req, res) => {
  let user = req.body;
  const validateResult = validateUser(user);

  if (validateResult.isSuccessful === true) {
    const hash = bcrypt.hashSync(user.password, 10);
    user.password = hash;
    
    Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
  } else {
    res.status(400).json({ 
      message: 'Invalid user input, see errors for details',
      errors: validateResult.errors
  });
 }
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {

        const token = getJwtToken(user.username);

        res.status(200).json({
          subject: `userId: ${user.id}`,
          token
        });
      } else {
        res.status(401).json({ message: 'You Shall Not Pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function getJwtToken(username) {
  const payload = { username };

  const secret = process.env.JWT_SECRET || 'is it secret, is it safe?';

  const options = { expiresIn: '1d' };

  return jwt.sign(payload, secret, options);
}

module.exports = router;
