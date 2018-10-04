const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

const loginCtrl = require('./controllers/loginCtrl');


app.use('/',express.static(__dirname + '/view/Login'));
app.use('/app',express.static(__dirname + '/view/Details'));
app.use('/userLogin', loginCtrl);

app.get('/', function (req, res) {
    res.sendFile(__dirname + '/view/Login/login.html')
});

app.get('/app/details', function (req, res) {
    res.sendFile(__dirname + '/view/Details/detail.html')
});

app.listen(3000, function () {
    console.log('Example app listening on port 3000!')
});

