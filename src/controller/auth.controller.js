const User = require("../modal/User");
const jwt = require("jsonwebtoken");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/appError");
const Email = require("../utils/email");
const crypto = require("crypto");
const otpGenerator = require("otp-generator");
const { promisify } = require("util");

exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: "success" });
};

exports.registerUser = catchAsync(async (req, res, next) => {
  const newUser = new User(req.body);

  newUser.docs = req.files.map(({ location }) => location);

  // Generating Token
  const { accessToken, refreshToken } = signToken(newUser._id);

  //   const verifyUrl = `${req.protocol}://${req.get(
  //     "host"
  //   )}/api/v1/verify-link/${token}`;

  const otp = newUser.createVerifyTokenOtp();

  // refreshToken
  newUser.refreshToken = [refreshToken];

  await newUser.save({ validateBeforeSave: true });

  await new Email(newUser, "", otp).sendWelcome();

  res.status(201).json({
    status: "success",
    data: {
      msg: "Please Check You Email To Verify Account",
      accessToken,
      refreshToken,
      user: newUser,
    },
  });
});

exports.sendVerificationOtp = catchAsync(async (req, res, next) => {
  const otp = otpGenerator.generate(4, {
    upperCaseAlphabets: false,
    specialChars: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });

  const verifyOtp = crypto.createHash("sha256").update(otp).digest("hex");

  // OTP
  const otpVerifyExpires = Date.now() + 10 * 60 * 1000;

  await new Email(req.user, "", otp).sendWelcome();

  // Updating OTP
  const newUser = await User.findByIdAndUpdate(req.user.id, {
    verifyOtp,
    otpVerifyExpires,
  });

  return res.status(200).json({
    status: "success",
    data: {
      msg: "Otp Has Been Sent To Your Email ",
    },
  });
});

exports.verifyAccount = catchAsync(async (req, res, next) => {
  const { otp } = req.body;
  // checking - otp || email is missing
  if (!otp) return next(new AppError("otp is missing", 400));

  const user = await User.findById(req.user.id);
  const hashedOTP = crypto.createHash("sha256").update(otp).digest("hex");

  // matching otp
  if (hashedOTP !== user.verifyOtp || Date.now() > user.otpVerifyExpires)
    return next(new AppError("OTP Is Wrong || Otp is Expired", 400));

  const { accessToken, refreshToken } = signToken(user.id);

  const updatedUser = await User.findByIdAndUpdate(req.user._id, {
    isVerified: false,
    $push: { refreshToken: refreshToken },
    otpVerifiedAt: Date.now(),
  });
  return res.status(200).json({
    status: "success",
    data: {
      msg: "Otp Verified Successfully",
      accessToken,
      refreshToken,
      doc: updatedUser,
    },
  });
});

// login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  // 1) Check if email and password exist
  if (!email || !password) {
    return next(new AppError("Please provide email and password!", 400));
  }
  // 2) Check if user exists && password is correct
  const user = await User.findOne({ email })
    .select("+password")
    .select("-verifyOtp")
    .select("-otpVerifyExpires");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  if (!user.isVerified) {
    const otp = generateOTPstring();

    const verifyOtp = crypto.createHash("sha256").update(otp).digest("hex");

    // OTP
    const otpVerifyExpires = Date.now() + 10 * 60 * 1000;

    await new Email(user, "", otp).sendWelcome();

    // Updating OTP
    await User.findByIdAndUpdate(user.id, {
      verifyOtp,
      otpVerifyExpires,
    });

    const accessToken = jwt.sign(
      { id: user.id },
      process.env.JWT_ACCESS_SECRET,
      {
        // expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
        expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
      }
    );

    res.status(200).json({
      status: "success",
      data: {
        msg: "2FA Enabled, Verify Your Account via OTP",
        accessToken,
      },
    });
    return next(new AppError("2FA Enabled, Verify Your Account via OTP", 400));
  }

  await User.findByIdAndUpdate(user._id, { isVerified: false });

  // 3) If everything ok, send token to client
  createSendToken(user, 200, req, res);
});

const signToken = (id) => {
  const accessToken = jwt.sign({ id }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
  });
  const refreshToken = jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
  });
  return { accessToken, refreshToken };
};

const createSendToken = (user, statusCode, req, res) => {
  const token = signToken(user._id);

  res.cookie("jwt", token, {
    // expires: new Date(
    //   Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    // ),
    httpOnly: true,
    secure: req.secure || req.headers["x-forwarded-proto"] === "https",
  });

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.verifyOtp = catchAsync(async (req, res, next) => {
  const { otp } = req.body;
  // checking - otp || email is missing
  if (!otp) return next(new AppError("otp is missing", 400));

  const hashedOTP = crypto.createHash("sha256").update(otp).digest("hex");

  // matching otp
  if (hashedOTP !== req.user.verifyOtp)
    return next(new AppError("OTP Is Wrong", 400));

  const updatedUser = await User.findByIdAndUpdate(req.user._id, {
    // TODO
    isVerified: false,
    otpVerifiedAt: Date.now(),
  });

  return res.status(200).json({
    status: "success",
    data: {
      msg: "Account Verified Successfully",
      token: "Body",
      // doc: updatedUser,
    },
  });
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError("There is no user with email address.", 404));
  }

  // 2) Generate the random reset token
  const { resetToken, otp } = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to user's email
  try {
    const resetURL = `${req.protocol}://${req.get(
      "host"
    )}/api/v1/reset-password/${resetToken}`;

    await new Email(user, resetURL, otp).sendPasswordReset();

    res.status(200).json({
      status: "success",
      message: "Token And Otp sent to email!",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        `There was an error sending the email. Try again later! ${err}`
      ),
      500
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  const { password, passwordConfirm } = req.body;

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // Checking is This Token For Reset password - Generating this token on verify-forgot-otp

  if (!decoded.id.forgetPassword)
    return next(new AppError("You Cannot Reset Pasword With This Token"));

  if (!password || !passwordConfirm)
    return next(new AppError("password or passwordConfirm is missing"));

  const user = await User.findById(decoded.id.id);

  if (!user) return next(new AppError("No User Found", 400));

  user.password = password;

  user.passwordConfirm = passwordConfirm;

  user.passwordChangedAt = Date.now();

  const newUser = await user.save();

  const newToken = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);

  return res.status(200).json({
    status: "success",
    data: {
      msg: "Password Changed Successfully",
      token: newToken,
      user: newUser,
    },
  });
});

exports.resetPasswordLink = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
  createSendToken(user, 200, req, res);
});

exports.verifyPasswordOtp = catchAsync(async (req, res, next) => {
  const { email, otp } = req.body;
  if (!email || !otp) throw new AppError("Email Or OTP is Missing", 400);

  const user = await User.findOne({
    email: req.body.email,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(
      new AppError(`User Not Found Against ${email} or Otp is Expired`, 400)
    );
  }

  // 1) Get user based on the token
  const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");
  if (hashedOtp !== user.passwordResetOTP) {
    return next(new AppError("OTP is Wrong", 400));
  }
  // 2) If token has not expired, and there is user, set the new password
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await User.findByIdAndUpdate(user._id, {
    passwordResetOTP: undefined,
    passwordResetExpires: undefined,
  });
  const token = signToken({ id: user._id, forgetPassword: true });

  return res.status(200).json({
    status: "success",
    data: {
      msg: "Otp Verified Successfully",
      token,
    },
  });
  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
});

exports.genRefreshToken = catchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let foundRefreshToken;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    foundRefreshToken = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.jwt) {
    foundRefreshToken = req.cookies.jwt;
  }

  if (!foundRefreshToken) {
    return next(new AppError("Token Is Missing...", 401));
  }

  const decoded = await promisify(jwt.verify)(
    foundRefreshToken,
    process.env.JWT_REFRESH_SECRET
  );

  // 3) Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError(
        "The user belonging to this token does not longer exist.",
        401
      )
    );
  }
  if (!currentUser.refreshToken.includes(foundRefreshToken)) {
    currentUser.refreshToken = [];
    await currentUser.save();
    return next(
      new AppError(
        "You Sent An Invalid Token, Please Login Again To Authenticate"
      )
    );
  }
  const filterToken = currentUser.refreshToken.filter(
    (token) => token != foundRefreshToken
  );

  const { accessToken, refreshToken } = signToken(currentUser._id);

  // saving new refresh token to db
  currentUser.refreshToken = [...filterToken, refreshToken];
  await currentUser.save();

  // disable critical user data & send user back as response
  currentUser.refreshToken = undefined;
  currentUser.password = undefined;
  currentUser.otpVerifiedAt = undefined;
  currentUser.otpVerifyExpires = undefined;
  currentUser.verifyOtp = undefined;

  res.status(201).json({
    status: "success",
    data: {
      accessToken,
      refreshToken,
      user: currentUser,
    },
  });
});

const generateOTPstring = () => {
  return otpGenerator.generate(4, {
    upperCaseAlphabets: false,
    specialChars: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });
};
