import jwt from 'jsonwebtoken';

export function requireAuth(req, res, next) {
  const authHeader = req.get('authorization');

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({
      error: 'Server configuration error',
      message: 'JWT_SECRET is not configured'
    });
  }

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Missing or invalid Authorization header'
    });
  }

  const token = authHeader.slice('Bearer '.length);

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    if (decodedToken.type !== 'access') {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Access token required'
      });
    }

    req.user = decodedToken;
    return next();
  } catch (error) {
    return res.status(401).json({
      error: 'Authentication failed',
      message: 'Invalid or expired token'
    });
  }
}

export function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const roles = allowedRoles.flat().filter(Boolean);

    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Login is required to access this resource'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have permission to access this resource'
      });
    }

    return next();
  };
}
