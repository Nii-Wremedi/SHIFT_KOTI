export function notFound(req, res) {
  res.status(404).json({
    error: 'Not found',
    message: `Route ${req.method} ${req.originalUrl} does not exist`
  });
}

export function errorHandler(error, req, res, next) {
  console.error(error);

  res.status(500).json({
    error: 'Server error',
    message:
      process.env.NODE_ENV === 'production'
        ? 'Something went wrong'
        : error.message || 'Something went wrong'
  });
}
