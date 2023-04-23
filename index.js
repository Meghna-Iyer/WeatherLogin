const express = require('express')
const bodyParser = require('body-parser')
const dotenv = require('dotenv')
const bcrypt = require('bcryptjs')
const DBUtilService = require('./DBUtilService')
var jsonParser = bodyParser.json()

const app = express()

dotenv.config({ path: './.env'})

const port = process.env.WEATHER_LOGIN_PORT

app.get("/verify_user", jsonParser, (req, res) => {
  let accessToken = req.query['access_token'];

  DBUtilService.verifyUser(accessToken, (err, result) => {
    if(err) {
      console.log(err)
      res.send(500, { message : "Verification unsuccessful!!!!!!"})
    }
    
    if(result.length == 1)
      return res.send(200, {message : "User verified"})
    else
      return res.send(403, { message : "Unauthenticated user"})
  })
})

app.post("/auth/login", jsonParser, (req, res) => {
  const { email, password } = req.body

  DBUtilService.getUserDataByEmail(email, (err, result) => {
    if(err) {
      console.log(err)
      return res.send(500, { message : "Login unsuccessful!!!!!!"})
    }

    if(result.length > 0) {
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

  DBUtilService.getUserDataByEmail(email, (err, result) => {
    if(err) {
      console.log(err)
      return res.send(500, { message : "Registeration unsuccessful!!!!!!"})
    }
    
    if(result.length > 0) {
      return res.send(400, { message : "Email already registered"})
    } else if(password !== password_confirm) {
      return res.send(400, { message : "Password doesn't match"})
    }    

    let hashedPassword = bcrypt.hashSync(password, 8)

    DBUtilService.insertUser(name, email, hashedPassword, (err, result) => {
      if(err) {
        console.log(err)
        return res.send(500, { message : "Registeration unsuccessful!!!!!!"})
      } else {
        return res.send(200, { id: result.insertId, accessToken : hashedPassword})
      }
    })

  })
})

app.listen(port, () => {
  console.log(`Weather Login app listening on port ${port}`)
})