// ==UserScript==
// @include https://*
// ==/UserScript==

function autoFill() {
  var elem = document.querySelector("div[id=passwordError]");
  if (elem) {
    return;
  }

  var elem = document.querySelector("input[type=email]");
  if (elem) {
    elem.dispatchEvent(new Event("focus"));
    elem.value = "$USERNAME";
    elem.dispatchEvent(new Event("blur"));
  }

  var elem = document.querySelector("input[type=password]");
  if (elem) {
    elem.dispatchEvent(new Event("focus"));
    elem.value = "$PASSWORD";
    elem.dispatchEvent(new Event("blur"));
  }

  var elem = document.querySelector("input[type=submit]");
  if (elem) {
    elem.dispatchEvent(new Event("focus"));
    elem.click();
  }
  setTimeout(autoFill, 1000);
}
autoFill();
