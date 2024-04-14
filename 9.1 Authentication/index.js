import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt, { hash } from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import {Strategy} from 'passport-local';
import env from 'dotenv';

const db = new pg.Client({
  user:'postgres',
  password:'manikantasdb',
  port:5432,
  host:'localhost',
  database:'secrets'
});
const saltRounds = 9;
db.connect();
env.config();

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  resave:false,
  secret:process.env.SESSION_SECRET,
  saveUninitialized:true,
  cookie:{
    maxAge: 1000*60*60*24
  }
  }
));
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req,res)=>{
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  console.log(req.body);
  const username = req.body.username;
  const password = req.body.password;
  // const result =await db.query(`insert into users (email,password) values ($1,$2)`,[username,password]);
  try {
    const result = await db.query('select * from users where email = $1',[username,]);
    if(result.rows.length>=1){
      res.send('The User already registered');
    }else{
      bcrypt.hash(password,saltRounds,async (err,hash)=>{
        if (err) {
          console.log("the error hasing password:",err);
        } else {
          const resu = await db.query("insert into users (email,password) values ($1, $2) returning *",[username,hash]);
          const user = resu.rows[1-1];
          req.login(user,(err)=>{
            console.log(err);
            res.redirect("/secrets")
          })
          res.render("secrets.ejs");
        }
      })
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login"
}));

passport.use(new Strategy(async function verify(username,passport,cb){
  try {
    const result = await db.query('select * from users where email=$1',[username]);
    if (result.rows.length >=1) {
      const user = result.rows[1-1];
      const savedPassword = user.password;
      bcrypt.compare(password,savedPassword,(err,result)=>{
        if (err) {
          return cb(err);
        } else if(result){
          return cb(null,user);
        }else{
          return cb(null, false);
        }
      });
    } else {
      return cb("user not found");
    }
  } catch (error) {
    return cb(err);
  }
}));

passport.serializeUser((user,cb)=>{
  cb(null, user);
});

passport.deserializeUser((user,cb)=>{
  cb(null,user);
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
