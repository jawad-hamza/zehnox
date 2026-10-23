"use strict";
/* Entry point for `node --test tests/mail/`.

   Node 22+ reads the arguments of `node --test` as file globs, so a bare directory is run
   as a module: `node --test tests/mail/` executes `node tests/`, which resolves to this file.
   It loads every tests/*.test.js into this one process, so their node:test cases register
   and report as usual. The glob form, `node --test "tests/**\/*.test.js"`, runs each file
   in its own process instead and never loads this file (it is not a *.test.js name).
   Every file keeps its own port slice (helpers/common.js PORTS), so both forms work. */

const fs = require("fs");
const path = require("path");

for (const name of fs.readdirSync(__dirname).filter((n) => n.endsWith(".test.js")).sort()) {
  require(path.join(__dirname, name));
}
