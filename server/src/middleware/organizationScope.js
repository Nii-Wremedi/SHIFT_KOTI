export function requireOrganizationContext(req, res, next) {
  if (req.user?.role === 'SUPER_ADMIN') {
    return next();
  }

  if (!req.user?.organizationId) {
    return res.status(403).json({
      error: 'Organization required',
      message: 'This action requires an organization workspace'
    });
  }

  req.organizationId = req.user.organizationId;
  return next();
}

export function requireSameOrganization(getOrganizationId) {
  return (req, res, next) => {
    if (req.user?.role === 'SUPER_ADMIN') {
      return next();
    }

    const organizationId = getOrganizationId(req);

    if (!organizationId || organizationId !== req.user?.organizationId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have access to this organization workspace'
      });
    }

    req.organizationId = organizationId;
    return next();
  };
}
