const { Pool } = require('pg');

const pool = new Pool({
    username: '',
    password: process.env.DB_PASSWORD,
    host: process.env.BD_HOST,
    port: '',
    database: '',
}, 
    sslmode = require);

const query = (text, param) => {
    return pool.query(text, param);
}

module.exports = {
    query
}

