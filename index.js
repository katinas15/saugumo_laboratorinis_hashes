const password = 'qwerty'

const crypto = require('crypto')
const hash = async (password, hashType, salt) => {
    const hasher = crypto.createHash(hashType)
    hasher.update(password + salt)
    const hash = await hasher.digest('hex').toString()
    return hash.toString()
}


const aes = (password, tekstas) => {
    var mykey = crypto.createCipher('aes-128-cbc', password);
    var mystr = mykey.update(tekstas, 'utf8', 'hex')
    mystr += mykey.final('hex');
    return mystr
}


const bcrypt = require('bcrypt');
const saltRounds = 10;

const hashBcrypt = async (password) => {
    /*

        $2b$10$nOUIs5kJ7naTuTFkBy1veuK0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa
        |  |  |                     |
        |  |  |                     hash-value = K0kSxUFXfuaOKdOKf9xYT0KKIGSJwFa
        |  |  |
        |  |  salt = nOUIs5kJ7naTuTFkBy1veu
        |  |
        |  cost-factor => 10 = 2^10 rounds
        |
        hash-algorithm identifier => 2b = BCrypt

    */
    return new Promise(resolve => {
        bcrypt.hash(password, saltRounds, function(err, hash) {
            resolve(hash);
        });
    })
}

const jwt = require('jsonwebtoken')
const JWT_SECRET = 'secret'
const JWT_EXPIRATION = '10s'
const generateToken = (data) => {
    return jwt.sign(data, JWT_SECRET, {
            expiresIn: JWT_EXPIRATION
        })
    
}


const start = async () => {
    //unsalted slaptazodziai gali buti paveikti dictionary ataku
    console.log('PLAIN TEXT - \t\t' + password  + '\n')

    //naudoja 128bit sifravimas, bet nebera saugus. dar daznai naudojamas vietisumo tikrinimui, taip pat greitesnis uz sha2 todel tinka dideliems failams
    console.log('MD5 - \t\t\t' + await hash(password, 'md5')  + '\n')
    //128bit
    console.log('MDC2 - \t\t\t' + await hash(password, 'mdc2') + '\n')

    //naudoja 160bit, bet del saugumo spragu nera naudojamas
    console.log('SHA1 - \t\t\t' + await hash(password, 'sha1') + '\n')

    //nera pats geriausias, bet tinkamas
    console.log('SHA256 - \t\t' + await hash(password, 'sha256') + '\n')
    //256 kn
    console.log('SM3 - \t\t\t' + await hash(password, 'sm3') + '\n')
    console.log('SHA384 - \t\t' + await hash(password, 'sha384') + '\n')
    console.log('SHA512 - \t\t' + await hash(password, 'sha512') + '\n')
    


    console.log('SHA256 + salt - \t' + await hash(password, 'sha256', 'salt') + '\n')
    console.log('BCRYPT + salt - \t' + await hashBcrypt(password) + '\n')

    console.log('JWT \t\t\t' + generateToken({name: 'Laimonas'}) + '\n')

    console.log('AES - \t\t\t' + await aes(password, 'tekstas') + '\n')
}

start()
