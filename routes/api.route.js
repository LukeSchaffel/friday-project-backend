const router = require('express').Router();
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const authenticateToken = require('../middleware/auth.js').authenticateToken
require('dotenv').config()



//--------public routes

//sign in
router.post('/users/login', async (req, res, next) => {

  const user = await prisma.user.findUnique({
    where: {
      email: req.body.email
    }
  })
  if (!user) {
    return res.status(400).send('Username or Password is incorrect')
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      console.log('login successful');
    } else {
      res.send('Invalid Username or Password')
      return
    }
  } catch (error) {
    res.status(500).send
  }
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)

  res.json({
    accessToken: accessToken,
    user: user
  })
});



//create user
router.post('/users/signup', async (req, res, next) => {
  const exists = await prisma.user.count({
    where: {
      email: req.body.email
    }
  })
  if (exists) {
    res.send("A user with this Email Already Exists")
    return
  }
  const validateEmail = (email) => {
    return String(email)
      .toLowerCase()
      .match(
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
      );
  };
  if (validateEmail(req.body.email) === null) {
    return res.status(501).send('Please Enter a Valid Email Address')
  }
  try {
    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(req.body.password, salt)
    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
      }
    })
    res.json(user)
  } catch (error) {
    console.log(error)
    next(error)
  }
});



// ------------ protected routes



//get all users
router.get('/users', authenticateToken, async (req, res, next) => {
  const authorized = req.user.role === 'ADMIN' ? true : false
  if(!authorized) {
    return res.status(401).send('invalid permissions')
  }
  try {
    const users = await prisma.user.findMany({})
    res.json(users)
  } catch (error) {
    console.log(error)
    throw error
  }
});


//get one user by ID
router.get('/users/:id', async (req, res, next) => {
  try {
    const { id } = req.params
    const user = await prisma.user.findUnique({
      where: {
        id: id
      }
    })
    res.json(user)
  } catch (error) {
    console.log(error)
    throw error
  }
});


//update user
router.patch('/users/:id',authenticateToken, async (req, res, next) => {
  const authorized = req.user.role === 'ADMIN' || req.user.id === req.params.id ? true : false
  if(!authorized) {
    console.log('invalid permissions');
    return res.status(401).send('invalid permissions')
  }
  
  try {
    const { id } = req.params
    const user = await prisma.user.update({
      where: {
        id: id
      },
      data: {
        name: req.body.name
      }
    })
    res.json(user)
  } catch (error) {
    console.log(error)
    next(error)
  }
});

//delete user
router.delete('/users/:id', authenticateToken, async (req, res, next) => {
  const authorized = req.user.role === 'ADMIN' || req.user.id === req.params.id ? true : false
  if(!authorized) {
    return res.status(401).send('invalid permissions')
  }
  try {
    const { id } = req.params
    const deletedUser = await prisma.user.delete({
      where: {
        id: id
      }
    })
    res.json(deletedUser)
  } catch (error) {
    next(error)
  }
});


module.exports = router;
