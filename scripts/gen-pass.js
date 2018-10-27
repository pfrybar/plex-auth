const bcrypt = require('bcrypt'),
      readline = require('readline'),
      Writable = require('stream').Writable

let muted = false
const mutableStdout = new Writable({
    write: (chunk, encoding, callback) => {
        if (!muted) {
            process.stdout.write(chunk, encoding)
        }
        callback()
    }
})

const rl = readline.createInterface({
    input: process.stdin,
    output: mutableStdout,
    terminal: true
})

rl.question('Password: ', async (password) => {
    const hash = await bcrypt.hash(password, 10)
    console.log()
    console.log(hash)
    rl.close()
})

muted = true
