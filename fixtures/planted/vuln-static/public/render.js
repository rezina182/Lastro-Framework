'use strict';

// FALHA PLANTADA (P-011): comentário do usuário escrito como HTML cru. CWE-79.
function showComment(el, userComment) {
  el.innerHTML = '<p class="comment">' + userComment + '</p>';
}
