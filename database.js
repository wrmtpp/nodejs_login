const mysql = require('mysql2');
const dbConnection = mysql.createPool({
    host     : "localhost",
    user     : "root", 
    password : "root", 
    database : "nodejs_login" // MYSQL DB NAME
}).promise();
module.exports = dbConnection;