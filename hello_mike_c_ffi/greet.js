var ffi = require('ffi')

var libgreet = ffi.Library('./libgreet', {
  'greet': [ 'string', [ 'string' ] ]
})

if (process.argv.length < 3) {
  console.log('Arguments: ' + process.argv[0] + ' ' + process.argv[1] + ' <max>')
  process.exit()
}

var output = libgreet.greet(process.argv[2])

console.log('Your output: ' + output)