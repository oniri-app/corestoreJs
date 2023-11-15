var browserify = require("browserify");
var reactify = require("reactify");
var babelify = require("babelify");
const fs = require("fs");

var writeStream = fs.createWriteStream("./dist/index.js");
var b = browserify({
  entries: [
    "./src/index.js", // THIS LINE HAS CHANGED FROM THE QUESTION
  ],
  standalone: "CorestoreModule",
}); //{ bare: true, browserField: true } {node:true}

b.transform(babelify, {
  presets: ["@babel/preset-env", "@babel/preset-react"],
})
  .bundle()
  .pipe(writeStream);
//b.bundle().pipe(writeStream);
