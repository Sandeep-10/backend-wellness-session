const express = require('express');
const app = express();
const {open} = require('sqlite');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const path = require("path");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
const dbPath = path.join(__dirname, "goodWellnes.db");
let db = null;
const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        });
        
        await db.exec(`
            CREATE TABLE IF NOT EXISTS User (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await db.exec(`
            CREATE TABLE IF NOT EXISTS Session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                tags TEXT,
                status TEXT CHECK(status IN ('draft', 'published')),
                json_file_url TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        app.listen(5000, () => {
            console.log("Server Running at http://localhost:5000/");
        });
    } catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(1);
    }
};

initializeDBAndServer();


app.post("/login", async(request,response)=>{
    const {email, password} = request.body;
    const checkUserQuery=`SELECT * FROM User WHERE email=?`;
    const user = await db.get(checkUserQuery, [email]);
    if (user===undefined){
        response.status(400);
        response.send({"error": "User Not Found"});
    }else{
        const ispasswordmatch = await bcrypt.compare(password, user.password_hash);
        if (ispasswordmatch){
            const payload = {
                email: user.email,
                user_id: user.id,
            }
            const jwtToken = jwt.sign(payload, "My-secret-key");
            response.status(200);
            response.send({jwtToken});
        }else{
            response.status(400);
            response.send(
                {"error": "Invalid Password"}
            );
        }
    }
})

app.post("/login/register", async(request, response) => {
    const {email, password} = request.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const checkUserQuery=`SELECT * FROM User WHERE email=?`;
    const user = await db.get(checkUserQuery, [email]);
    if (user===undefined){
        const createUserQuery=`INSERT INTO User (email, password_hash) VALUES (?, ?)`;
        await db.run(createUserQuery, [email, hashedPassword]);
        response.status(200);
        response.send({"message": "User Created Successfully"});
    }else{
        response.status(400);
        response.send({"error": "User Already Exists"});
    }
})


const authenticateToken = (request, response, next) => {
    let jwtToken
    const token = request.headers["authorization"];
    if (token!==undefined) {
         jwtToken = token.split(" ")[1]
    }
    if (jwtToken===undefined){
        response.status(400)
        response.send("Invalid User")
    }
    else{
        jwt.verify(jwtToken,"My-secret-key",async(error,payload)=>{
            if (error){
                response.status(400)
                response.send("Invalid Jwt Token")
            }
            else{
                request.user_id = payload.user_id
                next();
            }
        })
    }
}

app.get("/sessions", authenticateToken, async(request,   response) => {
    const getSessionsQuerys = `SELECT * FROM Session ORDER BY created_at`;
    const sessions = await db.all(getSessionsQuerys);
    response.send(sessions);
});

app.get("/my-sessions",authenticateToken, async(request, response) => {
    const user_id = request.user_id;
    const getSessionsQuery = `SELECT * FROM Session WHERE user_id=?`;
    const sessions = await db.all(getSessionsQuery, [user_id]);
    response.send(sessions);
});

app.get("/my-sessions/:id",authenticateToken,async(request,response)=>{
    const user_id = request.user_id;
    const {id} = request.params;
    const getSessionQuery = `SELECT * FROM Session WHERE id=? AND user_id=?`;
    const session = await db.get(getSessionQuery, [id,user_id]);
    response.send(session);
})

app.post("/my-sessions/save-draft",authenticateToken,async(request,response)=>{
    const user_id = request.user_id;
    const {title,tags,json_file_url,status} = request.body;
    const createSessionQuery = `INSERT INTO Session (user_id,title,tags,json_file_url,status) VALUES (?,?,?,?,?)`;
    await db.run(createSessionQuery, [user_id,title,tags,json_file_url,status]);
    response.send({"message": "Session saved as draft successfully"});
})

app.post("/my-sessions/publish",authenticateToken,async(request,response)=>{
    const user_id = request.user_id;
    const {session_id} = request.body;
    const publishSessionQuery = `UPDATE Session SET status='published' WHERE id=? AND user_id=?`;
    await db.run(publishSessionQuery, [session_id,user_id]);
    response.send({"message": "Session published successfully"});
}) 
