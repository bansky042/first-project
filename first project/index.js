import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session(
  {
    secret: "TOPWORLLDSECRET",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24
    },
  }
));
app.use(passport.initialize());
app.use(passport.session());


const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "practice",
  password: "bansky@100",
  port: 5432,
});
db.connect();


app.get("/", (req, res) => {
  res.render("index2.ejs");
});

app.get("/pricing", (req, res) => {
  res.render("pricing.ejs");
});

app.get("/personelTrainer", (req, res) => {
  res.render("personelTrainer.ejs");
});

app.get("/schedule", (req, res) => {
  res.render("schedule.ejs");
});

app.get("/testimonals", (req, res) => {
  res.render("testimonials.ejs");
});

app.get("/login", (req,res) => {
  res.render("login.ejs");
});

app.get("/register", (req,res) => {
  res.render("register.ejs");
});


app.get("/index", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("index.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/forgottenpassword", (req,res) => {
  res.render("forgottenPassword.ejs");
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/index",
  failureRedirect: "/login",
}));

app.post("/forgottenpassword", async (req, res) => {
  const email = req.body.username;
  const phoneNumber = req.body.phoneNumber;
   const newPassword = req.body.newPassword;
  

try {
  const result = await db.query("SELECT * FROM users WHERE email = $1",  [
    email,
  ]);

  if (result.rows.length > 0) {
    const user = result.rows[0];
    const storedPhoneNumber = user.phonenumber;
      
      
        if (phoneNumber === storedPhoneNumber) {
      
         bcrypt.hash(newPassword, saltRounds, async (err, hash) => {

          if (err) {
            console.error("Error hashing password:", err);
          } else {
            console.log("Hashed Password:", hash);

            await db.query("UPDATE users SET password = $1 WHERE email = $2",  [
              hash, email,
            ]);
           
            res.render("index.ejs");
          }

         }); 
          
          
          
       } else {

         res.send("incorrect phone number or email");

       };
   
  } else {
    res.send("phone number incorrect");
  }
} catch (error) {
  console.log(error);
}


});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const phoneNumber = req.body.phoneNumber;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1",  [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          await db.query(
            "INSERT INTO users (email, password, phoneNumber) VALUES ($1, $2, $3)",
            [email, hash, phoneNumber,

          ]);
          res.render("index.ejs");
          console.log(email);
          
          console.log(phoneNumber);
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});



passport.use(new Strategy(async function verify(username, password, cb){
console.log(username);


  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        }
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    return cb(err);
  }
}));
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
