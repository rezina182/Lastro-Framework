'use strict';

// Gêmea limpa de P-011: o texto do usuário entra como texto, não como HTML.
function showComment(el, userComment) {
  el.textContent = userComment;
}
