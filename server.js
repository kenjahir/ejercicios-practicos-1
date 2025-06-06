const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

app.use(bodyParser.json());

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/ejercicios-practicos-1');

// Ruta principal
app.get('/', (req, res) => {
  res.send('Servidor funcionando correctamente');
});

// Modelo de usuario
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// Middleware de autenticación
const authMiddleware = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).send('Token requerido');
  }
  jwt.verify(token, 'secreto', (err, user) => {
    if (err) {
      return res.status(403).send('Token inválido');
    }
    req.user = user;
    next();
  });
};

// Rutas CRUD

// Crear usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.status(201).send('Usuario registrado');
});

// Login (para obtener el token)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(404).send('Usuario no encontrado');
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(403).send('Contraseña incorrecta');
  }
  const token = jwt.sign({ id: user._id }, 'secreto');
  res.json({ token });
});

// Ver perfil de usuario
app.get('/profile', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) {
    return res.status(404).send('Usuario no encontrado');
  }
  res.json({ username: user.username, id: user._id });
});

// Actualizar usuario
app.put('/update', authMiddleware, async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.findByIdAndUpdate(req.user.id, {
    username: username,
    password: hashedPassword,
  }, { new: true });
  
  if (!user) {
    return res.status(404).send('Usuario no encontrado');
  }

  res.json({ message: 'Usuario actualizado', user });
});

// Eliminar usuario
app.delete('/delete', authMiddleware, async (req, res) => {
  const user = await User.findByIdAndDelete(req.user.id);
  if (!user) {
    return res.status(404).send('Usuario no encontrado');
  }

  res.json({ message: 'Usuario eliminado' });
});

// Iniciar servidor
app.listen(4000, () => {
  console.log('Servidor corriendo en http://localhost:4000');
});