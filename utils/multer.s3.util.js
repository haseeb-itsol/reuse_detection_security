const multerS3 = require("multer-s3");
const multer = require("multer");
const path = require("path");

const s3 = require("./s3.util");

const upload = multer({
  storage: multerS3({
    s3,
    acl: "public-read",
    bucket: "10myle",
    contentType: multerS3.AUTO_CONTENT_TYPE,
    key: (req, file, cb) => {
      const fileName = `${Date.now()}_${Math.round(Math.random() * 1e9)}`;
      cb(null, `${fileName}${path.extname(file.originalname)}`);
    },
  }),
});

exports.profilePhotoUpload = upload.single("photo");

exports.docUpload = upload.array("docs", 20);

exports.projectDocsUpload = upload.fields([
  { name: 'imageCover', maxCount: 1, },
  { name: 'docs', maxCount: 20, },
]);

exports.multy = upload.fields([
  { name: "imageCover", maxCount: 1 },
  { name: "images", maxCount: 10 },
]);
