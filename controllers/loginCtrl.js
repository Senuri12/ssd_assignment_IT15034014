const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const app = express();

let saltValue = null;
let csrfToken = null;
let sessionId = null;

/*
Geneates and stores to the server the session id,csrf Token and the salt if the user is a valid user
Add the cookie
*/
router.post('/userAuthenticate',(req,res) => {

        if(req.body.username == "John" && req.body.pass == "abc123"){
            sessionId = genSessionId();
            saltValue = genRanSalt(14);
            csrfToken = genCSRTToken(sessionId,saltValue);


            res.cookie('sessionId', sessionId, { maxAge: 900000, httpOnly: false });

            res.redirect('/app/details')
        }
        else {
            res.json({ success: false, message: 'Invalid Username or Password' });
        }
});


/*
pass the CSRF token if the session is valiid
*/
router.post("/getCsrfToken",(req,res) =>{
    var sesId = req.body.sessionId;
    if (sesId === sessionId)
    {
        res.json({ error: false, csrfToken: csrfToken });
    } else {
        res.json({ error: true });
    }
});


/*
redirect to th page with a success or failure message by checking the session id and the csrf token
*/
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


/*
generate the session id
*/
function genSessionId() {
    var sha = crypto.createHash('sha256');
    sha.update(Math.random().toString());
    return sha.digest('hex');
};


/*
generate the csrf token by adding the session id and the salt and sending it to a hash function
*/
function genCSRTToken(sessionId,saltvalue) {
    var hash = crypto.createHmac('sha512', saltvalue); /** Hashing algorithm sha512 */
    hash.update(sessionId);
    var value = hash.digest('hex');
    return value;
};


/*
generates a salt value
*/
function genRanSalt(length) {
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex')
        .slice(0,length);
};

module.exports = router;