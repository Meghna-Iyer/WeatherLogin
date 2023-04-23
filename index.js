const express = require('express')
const mysql = require('mysql2')
var bodyParser = require('body-parser')
const dotenv = require('dotenv')
const bcrypt = require('bcryptjs')
var jsonParser = bodyParser.json()
const app = express()

dotenv.config({ path: './.env'})

const port = 4005

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
})

db.connect((error) => {
  if(error) {
      console.log(error)
  } else {
      console.log("MySQL connected!")
  }
})

app.get("/verify_user", jsonParser, (req, res) => {
  const { accessToken } = req.body

  db.query('SELECT * FROM users WHERE password = ?', [accessToken], async (error, result) => {
      if(error) {
          console.log(error)
          return res.send(500, { message : "Verification unsuccessful!!!!!!"})
      }

      if( result.length == 1 ) {
        return res.send(200, {message : "User verified"})
      } else {
        return res.send(403, { message : "Unauthenticated user"})
      }
  })
})

app.post("/auth/login", jsonParser, (req, res) => {
  const { email, password } = req.body

  db.query('SELECT id, password as hash_pwd FROM users WHERE email = ?', [email], async (error, result) => {
      if(error) {
          console.log(error)
          return res.send(500, { message : "Login unsuccessful!!!!!!"})
      }

      if( result.length > 0 ) {
        var password_hash = result[0]["hash_pwd"];
        var id = result[0]["id"]

        const verified = bcrypt.compareSync(password, password_hash);
        if(verified) {
          return res.send(200, { id: id, accessToken : password_hash})
        }

        return res.send(400, { message : "Invalid login creds"})
      } else {
        return res.send(400, { message : "Invalid login creds"})
      }
  })
})


app.post("/auth/register", jsonParser, (req, res) => {
  const { name, email, password, password_confirm } = req.body

  db.query('SELECT email FROM users WHERE email = ?', [email], async (error, result) => {
      if(error){
          console.log(error)
          return res.send(500, { message : "Registeration unsuccessful!!!!!!"})
      }

      if( result.length > 0 ) {
        return res.send(400, { message : "Email already registered"})
      } else if(password !== password_confirm) {
        return res.send(400, { message : "Password doesn't match"})
      }

      let hashedPassword = await bcrypt.hash(password, 8)

      db.query('INSERT INTO users SET?', {name: name, email: email, password: hashedPassword}, (err, result) => {
          if(err) {
            return res.send(500, { message : "Registeration unsuccessful!!!!!!"})
          } else {
            return res.send(200, { id: result.insertId, accessToken : hashedPassword})
          }
      })
  })
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})