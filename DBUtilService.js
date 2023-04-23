const mysql = require('mysql2')
const dotenv = require('dotenv')

dotenv.config({ path: './.env'})

initNewConnection = () => {
    let connection = mysql.createConnection({
        host: process.env.DATABASE_HOST,
        user: process.env.DATABASE_USER,
        password: process.env.DATABASE_PASSWORD,
        database: process.env.DATABASE
    })
    connection.connect()
    return connection;
}

module.exports = {
    initNewConnection: initNewConnection,

    verifyUser: (accessToken, callback) => {
        let connection = initNewConnection();
        connection.query({
            sql: "SELECT * FROM users WHERE password = ? ",
            values: [accessToken]
        }, function (error, result) {
            if (error) return callback(error);
            return callback(null, result);
        });
    },

    getUserDataByEmail: (email, callback) => {
        let connection = initNewConnection();
        connection.query({
            sql: "SELECT id, name, email, password as hash_pwd FROM users WHERE email = ?",
            values: [email]
        }, function (error, result) {
            if (error) return callback(error);
            return callback(null, result);
        });
    },

    insertUser: (name, email, password, callback) => {
        let connection = initNewConnection();
        connection.query({
            sql: "INSERT INTO users(name, email, password) VALUES(?, ?, ?)",
            values: [name, email, password]
        }, function (error, result) {
            if (error) return callback(error);
            return callback(null, result);
        });
    }

}