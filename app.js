const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const userRouter = require('./routes/userRoutes');
const tourRouter = require('./routes/tourRoutes');
const reviewRouter = require('./routes/reviewRoutes');

const app = express();

// 1. Global MIDDLEWARES
//Set Security http Headers
app.use(helmet());

//dev logging
if (process.env.NODE_ENV === 'development') app.use(morgan('dev'));

//Limit requests from same API
const limiter = rateLimit({
  max: 100,
  window: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour,',
});
app.use('/api', limiter);

//Body parser
app.use(
  express.json({
    limit: '10kb',
  })
);

//Data sanitization against NoSQL query injection
app.use(mongoSanitize());

//Data sanitization against NoSQL query injection
app.use(xss());

//serving static files
app.use(express.static(`${__dirname}/public`));

//prevent parameter pollution
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsAverage',
      'ratingsQuantity',
      'maxGroupSize',
      'difficulty',
      'price',
    ],
  })
);

// 2. ROUTES
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
