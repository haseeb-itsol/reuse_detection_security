const { S3Client } = require("@aws-sdk/client-s3");

const config = {
  region: "us-east-1",
  credentials: {
    accessKeyId: process.env.S3_ACCESS_ID,
    secretAccessKey: process.env.S3_SECRET_KEY,
  },
};
const s3 = new S3Client(config);

module.exports = s3;
