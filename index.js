
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

var username;

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    username = req.session.username;
    if (!req.session.authenticated) {
        res.send(`
        <form action='/signup' method='get'>
            <button> Sign Up </button>
            <br>
            <button type='submit' formaction='/login' formmethod='get'> Login </button>
        </form>
        `);
    } else {
        res.send(`
        <form action='/members' method='get'>
            <div>Hello, ${username} !</div>
            <br>
            <button>Go to Members Area</button>
            <br>
            <button formaction='/logout' formmethod='get'>Logout</button>
        </form>
        `);
    }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
        <input name='name' type='text' placeholder='name'>
        <br>
        <input name='email' type='text' placeholder='email'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
        <input name='email' type='text' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
    var html = "";
    let missingField = false;

    if (username && email && password) {
        const schema = Joi.object(
            {
                username: Joi.string().max(20).required(),
                email: Joi.string().required(),
                password: Joi.string().max(20).required()
            });

        const validationResult = schema.validate({ username, email, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/signup");
            return;
        }

        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
        console.log("Inserted user");
        req.session.authenticated = true;
        req.session.username = username;
        res.redirect('/members');
        return;
    } else {
        if (!username) {
            html += "Name is required<br>";
            missingField = true;
        }
        if (!email) {
            html += "Email is required<br>";
            missingField = true;
        }
        if (!password) {
            html += "Password is required<br>";
            missingField = true;
        }
        if (missingField) {
            html += "<br><a href='/signup'>Try Again</a>";
        }
        res.send(html);
        return;
    }
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(50).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    var html = "";

	console.log(result);
	if (result.length != 1) {
		console.log("email not found");
		// res.redirect("/login");
		// return;
        html += `
            Invalid email/password combination
            <br>
            <a href='/login'>Try Again</a>`;
        res.send(html);
        return
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;
		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		// res.redirect("/login");
        html += `
            Invalid email/password combination
            <br><br>
            <a href='/login'>Try Again</a>`;
        res.send(html);
		return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }
    var html = `
    You are logged in! ${req.session.username}
    `;
    res.send(html);
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    // var html = `
    // You are logged out.
    // `;
    // res.send(html);
    res.redirect('/');
});


app.get('/members', (req,res) => {
    if (req.session.authenticated) {
        let html = `<p>Hello, ${req.session.username}<p><br>`;
        // var cat = req.params.id;
        let cat = Math.floor(Math.random() * 3) + 1;

        if (cat == 1) {
            html += "Fluffy: <img src='/fluffy.gif' style='width:250px;'>";
        } else if (cat == 2) {
            html += "Socks: <img src='/socks.gif' style='width:250px;'>";
        } else if (cat == 3) {
            html += "NyanCat: <img src='/nyancat.gif' style='width:250px;'>";
        } else {
            html += `Invalid cat id: ${cat}`;
        }
        html += `<form action='/logout' method='get'><button>Sign out</button>`;
        res.send(html);
    } else {
        res.redirect('/logout');
    }
    
});


app.use(express.static(__dirname + "/public"));

app.get("/does_not_exist", (req, res) => {
    res.status(404);
    res.send(`Page not found - 404 <br><img src='/404.gif' style='width:250px;'>`);
})

app.get("*", (req,res) => {
	res.redirect('/does_not_exist');
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 


// {
//     "name": "demo",
//         "version": "1.0.0",
//             "description": "v1.0 - Simple Website using Node.js\r ===================================",
//                 "main": "index.js",
//                     "scripts": {
//         "test": "echo \"Error: no test specified\" && exit 1",
//             "start": "node index.js",
//                 "build": "npm update && webpack"
//     },
//     "author": "",
//         "license": "ISC",
//             "dependencies": {
//         "bcrypt": "^5.1.0",
//             "connect-mongo": "^4.6.0",
//                 "connect-mongodb-session": "^3.1.1",
//                     "dotenv": "^16.0.3",
//                         "express": "^4.18.2",
//                             "express-session": "^1.17.3",
//                                 "joi": "^17.8.4",
//                                     "mongodb": "^5.3.0",
//                                         "nodemon": "^2.0.22"
//     }
// }
