const dotenv = require('dotenv');
dotenv.config();

const JWT_SECRET = {
   token: process.env.JWT_SECRET
} 
module.exports = JWT_SECRET;