const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bodyParser = require('body-parser');
const commons = require('./routes/commons');
const cors = require('cors')
const app = express();
app.use(cors())
app.use(bodyParser.json());

app.post('/tfa/setup', (req, res) => {

    // -Genera un secret aleatorio en el conjunto de la A-Z a-z 0-9
    // -Genera la secret key en formato ASCII, HEX y base32
    // -Genera la URL utilizada por el código de Google Authenticator 
    // una url outpath TOTP, la cual utiliza una biblioteca de códigos QR 
    // para generar un código QR basado en la URL de Google Authenticator 
    // para obtener un código QR que puedas escanear en la aplicación.
    //******************************************** */
    // Ejemplo del response: 
    //{
    //     ascii: 'I^m7qUUlmQ',
    //     hex: '495e6d377155556c6d51',
    //     base32: 'JFPG2N3RKVKWY3KR',
    //     otpauth_url: 'otpauth://totp/name?secret=JFPG2N3RKVKWY3KR'
    // }

    const secret = speakeasy.generateSecret();

    //  Genera una URL otpauth:// compatible con Google Authenticator para pasar el secreto a un dispositivo móvil e instalarlo.
    //  Authenticator considera que los códigos TOTP son válidos durante 30 segundos. 
    //  Además, la aplicación presenta códigos de 6 dígitos al usuario. 
    //  Para generar un código QR adecuado, pasa la URL generada a un generador de códigos QR
    //  Ejemplo del response:
    //  otpauth://totp/name?secret=NAYDGQJ7M5WF42KH&issuer=NarenAuth%20v0.0 

    var url = speakeasy.otpauthURL({
        secret: secret.base32,
        label: commons.userObject.uname,
        issuer: 'IzziAuthenticator',
        encoding: 'base32'
    });

    // Generador de QR para que pueda ser escaneado
    // por Google Authenticator

    QRCode.toDataURL(url, (err, dataURL) => {
        commons.userObject.tfa = {
            secret: '',
            tempSecret: secret.base32,
            dataURL,
            tfaURL: url
        };

        return res.json({
            message: 'Success',
            tempSecret: secret.base32,
            dataURL,
            tfaURL: secret.otpauth_url
        });
    });
});

app.post('/tfa/verify', (req, res) => {

    let isVerified = speakeasy.totp.verify({
        secret: commons.userObject.tfa.tempSecret,
        encoding: 'base32',
        token: req.body.token,
    });


    if (isVerified) {
        console.log(`Verified`);

        commons.userObject.tfa.secret = commons.userObject.tfa.tempSecret;
        return res.send({
            "status": 200,
            "message": "Success"
        });
    }

    return res.send({
        "status": 403,
        "message": "Invalid Auth Code"
    });
});

app.listen(3000,()=>{
    console.log("********Start********");
})