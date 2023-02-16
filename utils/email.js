const nodemailer = require('nodemailer');
const catchAsync = require('./catchAsync');

const sendEmail = async (options) => {
  //create transported
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
    //Activate in gmail "less secure app" option
  });
  //define email options
  const mailOptions = {
    from: 'Rupak Korde <korderupak@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
    //html
  };
  //actually send the email
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
