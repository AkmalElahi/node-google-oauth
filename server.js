const fs = require("fs");
const path = require("path");
const https = require("https");
const helmet = require("helmet");
const express = require("express");
const passort = require("passport");
const cookieSession = require("cookie-session");
const { Strategy } = require("passport-google-oauth20");

require("dotenv").config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function vefrifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Profile", profile);
  done(null, profile);
}

passort.use(new Strategy(AUTH_OPTIONS, vefrifyCallback));

passort.serializeUser((user, done) => {
  done(null, user.id);
});

passort.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

app.use(helmet());

app.use(
  cookieSession({
    name: "session",
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);

app.use(passort.initialize());
app.use(passort.session());

function checkLoggedIn(req, res, next) {
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (isLoggedIn) {
    return next();
  }
  return res.status(401).json({ error: "You must logged in!" });
}

app.get(
  "/auth/google",
  passort.authenticate("google", {
    scope: ["email"],
  })
);

app.get(
  "/auth/google/callback",
  passort.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google called us back!");
  }
);

app.get("/auth/logout", (req, res) => {
  req.logout();
  res.redirect("/")
});

app.get("/failure", (req, res) => {
  res.send("Failed to log in!");
});

app.get("/secret", checkLoggedIn, (req, res) => {
  res.send("your secret it 42!");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log("server is up and running");
  });
