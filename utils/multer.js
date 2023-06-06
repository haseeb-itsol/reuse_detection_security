const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "../../public/docs"));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

const upload = multer({ storage: storage });

exports.docUpload = upload.array("docs", 20);

exports.profilePhotoUpload = upload.single("photo");

exports.projectDocsUpload = upload.fields({ imageCover: 1, docs: 20 });
