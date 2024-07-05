export const errorHandler = (err, req, res, next) => {
  if (err) {
    res.sendStatus(500);
  } else {
    next();
  }
};
