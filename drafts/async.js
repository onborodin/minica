
function func() {
  console.log('hi!');
}
setTimeout(func, 500);


var timerId = setInterval(function() {
  console.log('tik');
}, 1000);

setTimeout(function() {
  clearInterval(timerId);
  console.log( 'stop' );
}, 5000);

var timerId = setInterval(function() {
  console.log('tik');
}, 1000);

console.log('BOOM');
