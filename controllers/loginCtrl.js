const express = require('express');
const router = express.Router();
const crypto = require('crypto');
// const cookieParser = require('cookie-parser');

const app = express();
// app.use(cookieParser());

let saltValue = null;
let csrfToken = null;
let sessionId = null;


router.post('/userAuthenticate',(req,res) => {
        console.log("inside controller");
        console.log('body: ', req.body);
        if(req.body.username == "John" && req.body.pass == "abc123"){
            sessionId = genSessionId();
            saltValue = genRanSalt(14);
            csrfToken = genCSRTToken(sessionId,saltValue);

            console.log(sessionId);
            console.log(saltValue);
            console.log(csrfToken);

            res.cookie('sessionId', sessionId, { maxAge: 900000, httpOnly: false });


            // alert("logged in")
            console.log("loggrd in")
            res.redirect('/app/details')
        }
        else {
            res.json({ success: false, message: 'Invalid Username or Password' });
        }
});


router.post("/getCsrfToken",(req,res) =>{
    var sesId = req.body.sessionId;
    if (sesId === sessionId)
    {
        res.json({ error: false, csrfToken: csrfToken });
    } else {
        res.json({ error: true });
    }
});


router.post("/validateCsrfToken",(req,res)=> {
    var sessId = req.cookies.sessionId;
    var csrfTok = req.body.csrfToken;
    if (sessId == sessionId &&  csrfTok == csrfToken){
        res.redirect('/app/details?error=false');
    }
    else{
        res.redirect('/app/details?error=true');
    }
});


function genSessionId() {
    var sha = crypto.createHash('sha256');
    sha.update(Math.random().toString());
    return sha.digest('hex');
};


function genCSRTToken(sessionId,saltvalue) {
    var hash = crypto.createHmac('sha512', saltvalue); /** Hashing algorithm sha512 */
    hash.update(sessionId);
    var value = hash.digest('hex');
    return value;
};


function genRanSalt(length) {
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex')
        .slice(0,length);
};

module.exports = router;