const mongoose = require("mongoose");
const express = require("express");
const authRouter = require("./src/router/authRouter");
const path = require("path");
const errorMiddleware = require("./src/middleware/errorMiddleware");

const morgan = require("morgan");

const { multy } = require("./src/utils/multer.s3.util");

require("dotenv").config();

const app = express();

const port = process.env.PORT || 4000;

const mongoUrl = process.env.MONGO_URL.replace(
  "<PASSWORD>",
  process.env.MONGO_PASSWORD
);
app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));

app.use(express.static("public"));

app.use(express.json());

// form-data --url-encoded
app.use(
  express.urlencoded({
    extended: false,
  })
);

app.use(morgan("dev"));

app.get("/", (req, res) => res.send("Welcome To Fort Alpha!"));

app.use(`/api/${process.env.API_VERSION}`, authRouter);

app.use(errorMiddleware);

mongoose.connect(mongoUrl).then((_) => {
  console.log(`MONGO SERVER IS RUNNING OK`);
});

app.listen(port, () => console.log(`Server app listening on port ${port}!`));
