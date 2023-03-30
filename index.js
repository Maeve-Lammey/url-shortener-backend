const express = require('express')
const app = express()
const port = 3000

const config = require("./config.json")

const mariadb = require('mariadb');
const bcrypt = require('bcrypt');
const TOKEN_LENGTH = 8;

const pool = mariadb.createPool(config);

app.use(express.json())
app.use(express.urlencoded())

function genToken() {
    var token = "";
    for (var i = 0; i < TOKEN_LENGTH; i++) {
        token += String.fromCharCode(Math.floor(33 + 80 * Math.random()));
    }

    return token
}

function genTokenExpiration() {
    let time = new Date();
    const ONE_HOUR = 1000 * 60 * 60;
    time.setTime(time.getTime() + ONE_HOUR);
    return time
}

app.post("/new_user", async (req, res) => {
    const { username, email, password } = req.body;
    let conn;

    try {
        conn = await pool.getConnection();
        let hash = await bcrypt.hash(password, 10);
        let token = genToken();
        let expireTime = genTokenExpiration();

        let dbRes = await conn.query
        ("INSERT IGNORE INTO users_table (username, email, password, session_token, session_expire) VALUES (?, ?, ?, ?, ?)", [username, email, hash, token, expireTime]);
        
        if(dbRes.affectedRows == 0) {
            res.json("username or email already in use")
        } else {
            res.json({token: token});
        }

    } catch (err) {
        console.log(err);
        res.status(500).send("DB ERROR");
    } finally {
        if(conn) {
            conn.end();
        } 
    }
})

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const plaintextPassword = password;
    let conn;

    try {
        conn = await pool.getConnection();
        let rows = await conn.query
        ("SELECT password, is_active, is_deleted, session_token, session_expire FROM users_table WHERE username = ?;", [username]);

        if(rows.length == 0) {
            res.json({ success: false, reason: "account does not exist"});   
            return;
        } 

        const { password, is_active, is_deleted, session_token, session_expire} = rows[0];
        if(!await bcrypt.compare(plaintextPassword, password)) {
            res.json({ success: false, reason: "invalid password"});
            return;
        }

        if(!is_active) {
            res.json({success: false, reason: "inactive account"})
            return;
        }

        if(is_deleted) {
            res.json({success: false, reason: "account does not exist"})
            return;
        }

        var currentTime = new Date();
        if(currentTime.getDate() > (new Date(session_expire)).getDate()) {
            let token = genToken();
            let expireTime = genTokenExpiration();

            await conn.query("UPDATE users_table SET session_token = ?, session_expire = ? WHERE username = ?;", [token, expireTime, username]); 
            res.json({token: token});
        } else {
            res.json({token: session_token})
        }

    } catch (err) {
        console.log(err);
        res.status(500).send("DB ERROR");
    } finally {
        if(conn) {
            conn.end();
        } 
    }
})

app.post("/geturls", async(req, res) => {
    const { session_token } = req.body;
    let user_id;
    let conn;

    try {
        conn = await pool.getConnection();
        let rows = await conn.query
        ("SELECT id FROM users_table WHERE session_token = ?;", [session_token]);
        if (rows.length == 0) {
            res.json({success: false, reason: "session token invalid"})
            return;
        } else {
            user_id = rows[0].id;
        }

        let dbRes = await conn.query
        ("SELECT alias, url from link_table WHERE user_id = ?;", [user_id]);
 
        res.json(dbRes);


    } catch (err) {
        console.log(err);
        res.status(500).send("DB ERROR");
    } finally {
        if(conn) {
            conn.end();
        } 
    }

})

app.post("/createalias", async(req, res) => {
    const {session_token, alias, url} = req.body;
    let user_id;
    let conn;

    try {
        conn = await pool.getConnection();
        let rows = await conn.query
        ("SELECT id FROM users_table WHERE session_token = ?;", [session_token]);
        if (rows.length == 0) {
            res.json({success: false, reason: "session token invalid"})
            return;
        } else {
            user_id = rows[0].id;
        }


        let dbRes = await conn.query
        ("INSERT IGNORE INTO link_table (user_id, alias, url) VALUES (?, ?, ?)", [user_id, alias, url]);
        
        if(dbRes.affectedRows == 0) {
            res.json({success: false, reason: "alias in user"})
            return;
        } else {
            res.json({success: true});
        }

    } catch (err) {
        console.log(err);
        res.status(500).send("DB ERROR");
    } finally {
        if(conn) {
            conn.end();
        } 
    }

})

app.get("/u/:alias", (req, res) => {
    pool.query("SELECT url FROM link_table WHERE alias = ?;", req.params.alias)
        .then((rows) => {
            if (rows.length == 0) {
                res.status(404).send("No such url")
            } else {
                res.redirect(301, rows[0].url);
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).send("The DB ERROR")
        })
})


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})