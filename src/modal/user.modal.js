const crypto = require("crypto");
const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const otpGenerator = require("otp-generator");

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
  },
  lastName: {
    type: String,
  },

  phone: {
    type: Number,
  },
  email: {
    type: String,
    required: [true, "Please provide your email"],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "Please provide a valid email"],
  },
  profilePhoto: {
    type: String,
    // required: [true, "Please provide your profile photo!"],
  },
  role: {
    type: String,
    enum: ["owner", "contractor", "company"],
    default: "owner",
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    minlength: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, "Please confirm your password"],
    validate: {
      // This only works on CREATE and SAVE!!!
      validator: function (el) {
        return el === this.password;
      },
      message: "Passwords are not the same!",
    },
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  building: {
    type: String,
    required: [true, "Please provide your building name or number!"],
  },

  address_1: {
    type: String,
    required: [true, "Please provide your address_1"],
  },

  address_2: {
    type: String,
  },

  city: {
    type: String,
    required: [true, "Please provide your city"],
  },
  postalCode: {
    type: String,
    required: [true, "Please provide your building name or number!"],
  },

  dateOfBirth: {
    type: Date,
  },
  trade: {
    type: String,
  },
  url: {
    type: String,
  },

  companyName: {
    type: String,
  },

  companyUrl: {
    type: String,
  },

  url: {
    type: String,
  },
  docs: {
    type: [String],
  },

  playerId: {
    type: String,
  },

  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetOTP: String,
  passwordResetExpires: Date,
  verifyOtp: String,
  otpVerifyExpires: Date,
  otpVerifiedAt: Date,
  createdAt: { type: Date, default: Date.now() },
  refreshToken: [String],
});

userSchema.pre(/^find/, function (next) {
  // this points to the current query
  this.find({}).select("-passwordConfirm");
  next();
});

userSchema.pre("save", async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified("password")) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  // False means NOT changed
  return false;
};

userSchema.methods.createVerifyTokenOtp = function () {
  const otp = otpGenerator.generate(4, {
    upperCaseAlphabets: false,
    specialChars: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });

  this.verifyOtp = crypto.createHash("sha256").update(otp).digest("hex");

  // OTP
  this.otpVerifyExpires = Date.now() + 10 * 60 * 1000;

  return otp;
};

userSchema.methods.sendEmailOtp = async function () {
  const otp = otpGenerator.generate(4, {
    upperCaseAlphabets: false,
    specialChars: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });
  this.emailOtp = crypto.createHash("sha256").update(otp).digest("hex");
  //10 minutes
  this.emailOtpExpiresIn = moment(Date.now()).add(30, "m").toDate();
  await this.save();
  return otp;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  const otp = otpGenerator.generate(4, {
    upperCaseAlphabets: false,
    specialChars: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });

  // Reset TOKEN
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // OTP
  this.passwordResetOTP = crypto.createHash("sha256").update(otp).digest("hex");

  // OTP
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return { otp, resetToken };
};

const User = mongoose.model("User", userSchema);

module.exports = User;
