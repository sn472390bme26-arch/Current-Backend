"use strict";
function uuid() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}
module.exports = { v4: uuid };
