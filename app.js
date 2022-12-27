require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

const User = require("./models/User");

app.get("/", (req, res) => {
    res.status(200).json({ "message": "Welcome to our API!" });
});

app.get("/users/:id", checkToken, async (req, res) => {
    const id = req.params.id;

    const user = await User.findById(id, "-password");

    if (!user) { return res.status(404).json({ "message": "User not found!" }); }

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) { return res.status(401).json({ "message": "Access denied!" }) }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch (error) {
        res.status(400).json({ "message": "Invalid token!" });
    }
}

app.post("/auth/register", async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    if (!username) { return res.status(422).json({ "message": "The request must contains username!" }); }
    if (!email) { return res.status(422).json({ "message": "The request must contains email!" }); }
    if (!password) { return res.status(422).json({ "message": "The request must contains password!" }); }
    if (!confirmPassword) { return res.status(422).json({ "message": "The request must contains password confirmation!" }); }
    if (password !== confirmPassword) { res.status(422).json({ "message": "The password and password confirmation dosn't matches." }); }

    const userExists = await User.findOne({ "email": email });
    if (userExists) { res.status(422).json({ "message": "This email has already been registered." }); }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        username,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({ "message": "User created successfully!" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ "message": "An unexpected error occurred, please try again later!" });
    }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email) { return res.status(422).json({ "message": "The request must contains email!" }); }
    if (!password) { return res.status(422).json({ "message": "The request must contains password!" }); }

    const user = await User.findOne({ "email": email });
    if (!user) { return res.status(404).json({ "message": "User not found!" }); }

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) { return res.status(422).json({ "message": "Invalid password!" }); }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        );

        res.status(200).json({ "message": "Authenticated. JWT Token: ", token })
    } catch (error) {
        console.log(error);
        res.status(500).json({ "message": "An unexpected error occurred, please try again later!" });
    }

});

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose.set("strictQuery", false);
mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@apinodemongojwtcluster.wbuxkod.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000);
        console.log("Connected with MongoDB!");
    })
    .catch((err) => {
        console.log(err)
    });