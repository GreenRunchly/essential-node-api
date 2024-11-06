// DotEnv Config
require('dotenv').config(); // Load Configuration

// WebServer Library untuk handle incoming client, etc.
const cors = require('cors');
const express = require('express');
const validator = require('express-validator');
const jwt = require('jsonwebtoken');
const app = express();
app.use(cors()); // Menggunakan CORS agar api dapat dipakai oleh siapa saja (tanpa perlu origin server)
app.use(express.json()); // Untuk mengurai JSON
app.use(express.urlencoded({ extended: true })); // Untuk mengurai URL-encoded

// Password Encryption
const bcrypt = require('bcrypt');
const saltRounds = 10; // Number of rounds for salting, similar to cost factor in PHP
async function hashPassword(password) {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
}
async function verifyPassword(password, hashedPassword) {
    const isMatch = await bcrypt.compare(password, hashedPassword);
    return isMatch;
}

// Validasi input
function validatorResult(req, res, next) {
    const validation = validator.validationResult(req);
    if (!validation.isEmpty()) {
        res.status(200).json({
			code : 'error',
            msg : validation.errors[0].msg
        });
        return true;
    }else{
        return false;
    }
}

// Koneksi mysql
const mysql = require('mysql2');
const pooldb = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
	multipleStatements: true
});

// Middleware Token Auth
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];  // Bearer <token>

    if (token == null) return res.sendStatus(401);  // No token present

    jwt.verify(token, 'SECRET_KEY', (err, user) => {
        if (err) return res.sendStatus(403);  // Invalid token

        req.user = user;
        next();
    });
};

// REST API Stateless
app.post('/login', [
    validator.body('username').not().isEmpty().withMessage('Masukan username').trim().escape(),
	validator.body('password').not().isEmpty().withMessage('Masukan password').trim().escape()
], (req, res) => { if ( validatorResult(req, res) ){ return; }

	let {username, password} = req.body;

	let sqlsyn = ` SELECT * FROM user WHERE username=?; `;
	pooldb.query(sqlsyn, [username], async (err, result) => {
		if (err){ 
			console.log(err);
		} else {
            if (result[0]){
                let userData = result[0];
                hashedPassword = userData.password;
                
                verifyPassword(password, hashedPassword).then((isMatch) => {
                    if (isMatch) {
                        const token = jwt.sign({ username }, 'SECRET_KEY', { expiresIn: '1h' });
                        res.json({
                            code : "ok",
                            msg : "Berhasil Masuk!",
                            data : {
                                userData,
                                token
                            }
                        });
                    } else {
                        res.json({
                            code : "error",
                            msg : "Password salah!"
                        });
                    }
                });
            }else{
                res.json({
                    code : "error",
                    msg : "User tidak ditemukan"
                });
            }            
		}
	});
});

app.get('/check/:username', authenticateToken, (req, res) => { if ( validatorResult(req, res) ){ return; }

	let {username} = req.params;

	let sqlsyn = ` SELECT * FROM user WHERE username=?; `;
	pooldb.query(sqlsyn, [username], async (err, result) => {
		if (err){ 
			console.log(err);
		} else {
            if (result[0]){
                let userData = result[0];
                res.json({
                    code : "ok",
                    msg : "User ditemukan!",
                    data : {userData}
                });
            }else{
                res.json({
                    code : "error",
                    msg : "User tidak ditemukan!"
                });
            }            
		}
	});
});

app.get('/*', (req, res) => {
	res.json({
		code : "error",
		msg : "API Invalid"
	})
});

app.listen(process.env.HTTP_PORT, () => {
  	console.log(`Server dengan port ${process.env.HTTP_PORT} berjalan...`);
});

