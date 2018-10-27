const axios = require('axios'),
      bcrypt = require('bcrypt'),
      bodyParser = require('body-parser'),
      fs = require('fs'),
      session = require('express-session'),
      FileStore = require('session-file-store')(session),
      { URL } = require('url')

const signInUri = 'https://plex.tv/users/sign_in.json'
const getAccountUri = 'https://plex.tv/users/account.json'

const saltRounds = 10
const sessionName = 'auth.sid'
const sessionAgeSeconds = 60 * 60 * 24 * 7 // 7 days
const tokenCheckSeconds = 60 * 5 // 5 minutes

const port = 3000

// default config file: admin/adminPassword user/userPassword
const configFile = '/config/config.json'
var config = JSON.parse(fs.readFileSync(configFile))
console.log(config)

const express = require('express')
const app = express()

const fileStoreOptions = {
    fileExtension: '',
    secret: config.secret,
    ttl: sessionAgeSeconds
}

const sessionOptions = {
    cookie: { maxAge: sessionAgeSeconds * 1000 },
    name: sessionName,
    resave: false,
    rolling: true,
    saveUninitialized: false,
    secret: config.secret,
    store: new FileStore(fileStoreOptions)
}

console.log(app.get('env'))
if (app.get('env') === 'production') {
    app.set('trust proxy', 1)
    sessionOptions.cookie.secure = true
}

app.use((req, res, next) => {
    req.timeStarted = Date.now()
    next()
})

app.use(bodyParser.urlencoded({ extended: false }))
app.use(session(sessionOptions))

app.use((req, res, next) => {
    var user
    if (req.session.auth) {
        user = req.session.auth.user
    } else {
        user = 'Ø'
    }

    req.logPrefix = `<${user}> ${req.method} ${req.originalUrl}`

    res.on('finish', function() {
        const time = Date.now() - req.timeStarted
        log(req, `request took ${time} ms`)
    })

    next()
})

// TODO: better logging
app.get('/auth', async (req, res) => {
    if (!req.session.auth) {
        log(req, 'no authentication')
        return res.sendStatus(401)
    }

    const user = req.session.auth.user
    log(req, `found auth for user: ${user}`)

    if ( !(user in config.users) ) {
        log(req, `user is not in authorized list: ${user}`)
        await destroySession(req, res)
        return res.sendStatus(403)
    }

    const normalizedPath = new URL('http://dummy' + req.get('X-Auth-URI')).pathname

    var authorized = false
    for (var i=0; i<config.routes.length; i++) {
        const route = config.routes[i]

        if (normalizedPath.startsWith(route.path)) {
            log(req, `${normalizedPath} matched route ${route.path}`)

            if (config.users[user].groups.includes(route.restrict)) {
                log(req, 'user has correct authorization')
                authorized = true
            }
        }
    }

    if (!authorized) {
        log(req, 'could not find route with correct permissions')
        return res.sendStatus(403)
    }

    if (req.session.auth.type === 'plex') {
        const timeSinceTokenCheck = (Date.now() - req.session.auth.lastChecked)
        log(req, `been ${timeSinceTokenCheck/1000} seconds since last token check`)
        if (timeSinceTokenCheck > (tokenCheckSeconds * 1000)) {
            log(req, 'need to check token')

            try {
                await checkToken(req.session.auth.token)
                req.session.auth.lastChecked = Date.now()
            } catch (error) {
                console.warn(`token has been invalidated for: ${user}`)
                await destroySession(req, res)
                return res.sendStatus(403)
            }
        }
    }

    return res.sendStatus(204)
})

app.get('/login', (req, res) => {
    const errors = {
        '': '',
        invalid: 'invalid username and/or password',
        unauthorized: 'not authorized to view this site',
        'missing.user': 'missing username',
        'missing.pass': 'missing password'
    }

    const redirect = (('redirect' in req.query) && req.query.redirect.startsWith('/'))
          ? req.query.redirect
          : ''

    const errorCode = req.query.error ? req.query.error : ''
    const errorStyle = errorCode ? 'color:red;' : 'display: none;'
    const error = (errorCode in errors) ? errors[errorCode] : 'unknown error'

    res.send(`
<html>
  <body>
    <div style="${errorStyle}">
      Error: ${error}
    </div>
    <form action="/login" method="post">
      Login:<br>
      Username: <input type="text" name="user"><br>
      Password: <input type="password" name="pass"><br>
      <input type="hidden" name="redirect" value="${redirect}">
      <input type="submit" value="Login">
    </form>
  </body>
</html>`
    )
})

app.post('/login', async (req, res, next) => {
    const hasRedirect = (('redirect' in req.body) && req.body.redirect.startsWith('/'))
    const redirect = hasRedirect ? req.body.redirect : config.defaultRoute
    const redirectParam = hasRedirect ? `&redirect=${redirect}` : ''

    const user = req.body.user
    if (!user) {
        return res.redirect(`/login?error=missing.user${redirectParam}`)
    }

    if ( !(user in config.users) ) {
        log(req, `unknown user ${user}`)
        return res.redirect(`/login?error=invalid${redirectParam}`)
    }

    const pass = req.body.pass
    if (!pass) {
        return res.redirect(`/login?error=missing.pass${redirectParam}`)
    }

    const configUser = config.users[user]
    if (configUser.type === 'local') {
        const correct = await bcrypt.compare(pass, configUser.password)

        if (!correct) {
            log(req, 'incorrect local auth')
            return res.redirect(`/login?error=invalid${redirectParam}`)
        }

        log(req, 'local auth was successful')

        req.session.auth = {
            type: 'local',
            user: user
        }
    } else if (configUser.type === 'plex') {
        try {
            const plexUser = await authenticateUser(user, pass)
        } catch (error) {
            if (error.response && error.response.status === 401) {
                log(req, 'incorrect plex auth')
                return res.redirect(`/login?error=invalid${redirectParam}`)
            } else {
                return next(error)
            }
        }

        log(req, 'plex auth was successful')

        req.session.auth = {
            type: 'plex',
            user: plexUser.email,
            token: plexUser.authToken,
            lastChecked: Date.now()
        }
    } else {
        log(req, `unknown user type ${configUser.type}`)
        return res.redirect(`/login?error=unauthorized${redirectParam}`)
    }

    log(req, `redirecting to: ${redirect}`)

    return res.redirect(redirect)
})

app.get('/logout', async (req, res) => {
    try {
        if (req.session.auth) {
            await destroySession(req, res)
        }
    } catch (error) {
        log(req, 'error while logging out: ${error}')
    }

    return res.redirect('/login')
})

app.get('/admin', (req, res) => {
    const configString = JSON.stringify(config, null, 4)

    res.send(`
<html>
  <body>
    Config:
    <form action="/admin" method="post">
      <textarea name="config" rows="40" cols="100">${configString}</textarea><br>
      <input type="submit" value="Submit">
    </form>
  </body>
</html>`
    )
})

app.post('/admin', (req, res) => {
    const configString = req.body.config
    const newConfig = JSON.parse(configString)
    if ( !('groups' in newConfig) || !('users' in newConfig) || !('routes' in newConfig) ) {
        return res.sendStatus(500)
    }

    fs.writeFileSync(configFile, JSON.stringify(newConfig, null, 4))
    config = newConfig

    res.send('config successfully updated')
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))

function log(req, str) {
    const now = new Date()
    console.log(`[${now.toUTCString()}] ${req.logPrefix} - ${str}`)
}

function authenticateUser(user, pass) {
    const data = {
        user: {
            login: user,
            password: pass
        }
    }

    const config = {
        headers: getHeaders()
    }

    return axios.post(signInUri, data, config)
        .then(response => response.data.user)
}

function checkToken(token) {
    const config = {
        headers: getHeaders()
    }

    config.headers['X-Plex-Token'] = token

    return axios.get(getAccountUri, config)
        .then(response => response.data.user)
}

function getHeaders() {
    return {
        'X-Plex-Client-Identifier': 'f978bf40-17af-4be9-94ea-fc92a536f36e',
        'X-Plex-Product': 'Test Product',
        'X-Plex-Version': '3',
        'X-Plex-Device': 'Test (Web)',
        'X-Plex-Platform': 'Web'
    }
}

function destroySession(req, res) {
    return new Promise((resolve, reject) => {
        req.session.destroy((error) => {
            res.clearCookie(sessionName)
            if (error) {
                reject(error)
            } else {
                resolve()
            }
        })
    })
}
