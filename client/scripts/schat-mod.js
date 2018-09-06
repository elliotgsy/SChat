//Module Fix
if (typeof module === 'object') {window.module = module; module = undefined;}

//JQuery
window.jquery = require("jquery");
window.$ = window.jquery;

//Eval Security
window.eval = global.eval = function () {
    throw new Error(`Sorry, this app does not support window.eval() for security purposes.`)
}

