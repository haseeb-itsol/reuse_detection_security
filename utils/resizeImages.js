const multer = require("multer");
const sharp = require("sharp");
const AppError = require("./appError");
const catchAsync = require("./catchAsync");

const multerStorage = multer.memoryStorage();

const multerFilter = (req, file, cb) => {
  //   return cb(null, true);
  if (file.mimetype.startsWith("image")) {
    cb(null, true);
  } else {
    cb(new AppError("Not an image! Please upload only images.", 400), false);
  }
};

const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
});

exports.uploadUserPhoto = upload.single("profilePhoto");

let uploadAnythingStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/img/users");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const uploadAnything = multer({ storage: uploadAnythingStorage });

exports.uploadHostImages = upload.fields([
  { name: "idPhotos", maxCount: 2 },

  { name: "documents", maxCount: 10 },
]);

exports.resizeHostImages = catchAsync(async (req, res, next) => {
  if (!req.files.idPhotos || !req.files.documents)
    return next(new AppError("idPhotos or documents is missing"));
  req.body.idPhotos = [];
  req.body.documents = [];

  await Promise.all(
    req.files.idPhotos.map(async (file, i) => {
      let filename = `id-${Date.now()}-${i + 1}.jpeg`;

      await sharp(file.buffer)
        .resize(2000, 1333)
        .toFormat("jpeg")
        .jpeg({ quality: 90 })
        .toFile(`public/img/users/${filename}`);

      filename = `${req.protocol}://${req.get("host")}/img/users/${filename}`;
      req.body.idPhotos.push(filename);
    })
  );

  await Promise.all(
    req.files.documents.map(async (file, i) => {
      let filename = `document-${Date.now()}-${i + 1}.jpeg`;

      await sharp(file.buffer)
        .toFormat("jpeg")
        .toFile(`public/img/users/${filename}`);

      filename = `${req.protocol}://${req.get("host")}/img/users/${filename}`;
      req.body.documents.push(filename);
    })
  );

  next();
});

exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next(new AppError("profilePhoto is missing", 400));
  if (!req.file) return next();
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);

  req.file.filename = `user-${uniqueSuffix}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat("jpeg")
    .jpeg({ quality: 90 })
    .toFile(`public/img/users/${req.file.filename}`);

  // FOR RESOPNSE - IMAGE URL WITH HOST/DOMAIN
  req.file.filename = `${req.protocol}://${req.get("host")}/img/users/${
    req.file.filename
  }`;

  req.body.profilePhoto = req.file.filename;
  next();
});

exports.uploadServiceImages = upload.fields([
  { name: "imageCover", maxCount: 1 },
  { name: "images", maxCount: 10 },
]);

// upload.single('image') req.file
// upload.array('images', 5) req.files

exports.resizeServiceImages = catchAsync(async (req, res, next) => {
  if (!req.files?.imageCover || !req.files.images)
    return next(new AppError("ImageCover or images are missing", 400));

  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);

  const uniqueName = `service-cover-${uniqueSuffix}-${Date.now()}.jpeg`;

  // 1) Cover image

  await sharp(req.files.imageCover[0].buffer)
    .resize(2000, 1333)
    .toFormat("jpeg")
    .jpeg({ quality: 90 })
    .toFile(`public/img/service/cover/${uniqueName}`);

  req.body.imageCover = `${req.protocol}://${req.get(
    "host"
  )}/img/service/cover/${uniqueName}`;
  // 2) Images
  req.body.images = [];

  await Promise.all(
    req.files.images.map(async (file, i) => {
      let filename = `service-${Date.now()}-${i + 1}.jpeg`;

      await sharp(file.buffer)
        .resize(2000, 1333)
        .toFormat("jpeg")
        .jpeg({ quality: 90 })
        .toFile(`public/img/service/${filename}`);

      filename = `${req.protocol}://${req.get("host")}/img/service/${filename}`;
      req.body.images.push(filename);
    })
  );

  next();
});
