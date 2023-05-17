require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const usersRouter = require('./routes/users');

const app = express();

mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected!'))
  .catch((error) => console.error('MongoDB connection error:', error));

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));

// Middleware de validación de datos
const validateUserData = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    name: Joi.string().min(3).required(),
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  next();
};


// Middleware de validación de datos para el registro de usuarios
app.post('/users', validateUserData, async (req, res, next) => {
  try {
    if (req.body.password) {
      console.log('Original password:', req.body.password);
      req.body.password = await encryptPassword(req.body.password);
    }
    next();
  } catch (error) {
    console.error('Error in encryption middleware:', error);
    next(error);
  }
});

app.use('/users', usersRouter);

app.get('/', (req, res) => {
  res.redirect('/users');
});

// Función asincrónica para encriptar contraseñas con bcrypt
async function encryptPassword(plainTextPassword) {
  const saltRounds = 10;
  try {
    const encryptedPassword = await bcrypt.hash(plainTextPassword, saltRounds);
    console.log('Password:', plainTextPassword);
    console.log('Encrypted Password:', encryptedPassword);
    return encryptedPassword;
  } catch (error) {
    throw new Error('Error encrypting password');
  }
}

// Función para comparar contraseñas encriptadas con bcrypt
function comparePasswords(plainTextPassword, hashedPassword) {
  return bcrypt.compareSync(plainTextPassword, hashedPassword);
}

app.locals.comparePasswords = comparePasswords;

app.listen(process.env.PORT, () => {
  console.log(`Server started on port ${process.env.PORT}`);
});
