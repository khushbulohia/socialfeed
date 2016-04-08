require('./bootstrap') // Setup error handlers

let express = require('express')
let morgan = require('morgan')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let LocalStrategy = require('passport-local').Strategy
let nodeifyit = require('nodeifyit')
let co = require('co')
require('songbird')
let mongoose = require('mongoose')
let crypto = require('crypto')
let SALT = 'CodePathHeartNodeJS'
let flash = require('connect-flash')
let User = require('./user.js')


mongoose.connect('mongodb://127.0.0.1:27017/authenticator')


// Add in-memory user before app.listen()
let user = {
    email: 'foo@foo.com',
    password: crypto.pbkdf2Sync('asdf', SALT, 4096, 512, 'sha256').toString('hex')
}

const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000

let app = express()

// start server
app.listen(PORT, ()=> console.log(`Listening @ http://127.0.0.1:${PORT}`))


app.set('view engine', 'ejs')
app.use(session({
  secret: 'ilovethenodejs',
  resave: true,
  saveUninitialized: true
}))
app.use(flash())
// And add your root route after app.listen
// app.get('/', (req, res) => res.render('index.ejs', {message: req.flash('error')}))
// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))
// Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// In-memory session support, required by passport.session()

// Use the passport middleware to enable passport
app.use(passport.initialize())

// Enable passport persistent sessions
app.use(passport.session())
app.get('/', (req, res) => {
    res.render('index.ejs', {message: req.flash('error')})
})


passport.use(new LocalStrategy({
    usernameField: 'email', // Use "email" field instead of "username"
    failureFlash: true // Enables error messaging
}, nodeifyit(co.wrap(function* (email, password)  {
    email = (email || '').toLowerCase()
      console.log('LocalStrategy' + email)

    let user = yield User.promise.findOne({email})

    let passwordHash = yield crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')
   if (passwordHash.toString('hex') !== user.password) {
        return [false, {message: 'Invalid password'}]
    }
    return user
}), {spread: true})))



passport.use('local-signup', new LocalStrategy({
   usernameField: 'email'
}, nodeifyit(co.wrap(function* (email, password)  {
    email = (email || '').toLowerCase()

    if (yield User.promise.findOne({email})) {
        return [false, {message: 'That email is already taken.'}]
    }

    let user = new User()
    user.email = email

    // Store password as a hash instead of plain-text
    user.password = (yield crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')).toString('hex')
    return yield user.save()
}), {spread: true})))

// callbackFn.promise => promiseFn
// wrap(promiseFn) => callbackFn

passport.serializeUser(function (user, next) {console.log('ser');  next(null, user.email)})
passport.deserializeUser(

    co.wrap(function* (email, next){
      next(null, yield User.findOne({email}).exec())
    })

)
// co.wrap(function*) => promiseFn
// nodeifyit(promiseFn) => callbackFn
// passport.serializeUser(nodeifyit(co.wrap(function* (user) { console.log('1'); return user.email})))
// passport.deserializeUser(nodeifyit(co.wrap(function* (id) { console.log('2'); return user})))

// process the login form
app.post('/login', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/',
  failureFlash: false
}))


// process the signup form
app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: false
}))

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next()
    res.redirect('/')
}
app.get('/profile', isLoggedIn, (req, res) => res.render('profile.ejs', {}))
