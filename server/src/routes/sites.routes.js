import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../utils/prisma.js';

const router = Router();
const DEFAULT_TIMEZONE = 'Africa/Accra';

const siteSelect = {
  id: true,
  organizationId: true,
  name: true,
  address: true,
  timezone: true,
  active: true,
  createdAt: true,
  updatedAt: true,
  organization: {
    select: {
      id: true,
      name: true,
      industryType: true,
      status: true,
      active: true
    }
  }
};

function getScopedOrganizationId(req) {
  if (req.user.role === 'SUPER_ADMIN') {
    return req.body.organizationId?.trim() || req.query.organizationId?.toString().trim() || null;
  }

  return req.user.organizationId || null;
}

function getSiteAccessWhere(req, siteId) {
  const where = { id: siteId };

  if (req.user.role !== 'SUPER_ADMIN') {
    where.organizationId = req.user.organizationId;
  }

  return where;
}

function getOptionalBoolean(value) {
  return typeof value === 'boolean' ? value : undefined;
}

function handleSiteNotFound(res) {
  return res.status(404).json({
    error: 'Site not found',
    message: 'No accessible site exists with the provided siteId'
  });
}

async function getActiveOrganization(organizationId) {
  if (!organizationId) {
    return null;
  }

  return prisma.organization.findFirst({
    where: {
      id: organizationId,
      status: 'ACTIVE',
      active: true
    },
    select: {
      id: true,
      name: true,
      status: true,
      active: true
    }
  });
}

router.use(requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'));

router.post('/', async (req, res, next) => {
  try {
    const name = req.body.name?.trim();
    const address = req.body.address?.trim() || null;
    const timezone = req.body.timezone?.trim() || DEFAULT_TIMEZONE;
    const organizationId = getScopedOrganizationId(req);

    if (!name) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'name is required'
      });
    }

    if (!organizationId) {
      return res.status(400).json({
        error: 'Validation failed',
        message:
          req.user.role === 'SUPER_ADMIN'
            ? 'organizationId is required for SUPER_ADMIN site creation'
            : 'Admin users must belong to an organization workspace'
      });
    }

    const organization = await getActiveOrganization(organizationId);

    if (!organization) {
      return res.status(404).json({
        error: 'Organization not found',
        message: 'No active organization exists with the provided organizationId'
      });
    }

    const site = await prisma.site.create({
      data: {
        organizationId,
        name,
        address,
        timezone
      },
      select: siteSelect
    });

    return res.status(201).json({
      message: 'Site created',
      site
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const organizationId = req.user.role === 'SUPER_ADMIN'
      ? req.query.organizationId?.toString().trim()
      : req.user.organizationId;

    if (req.user.role !== 'SUPER_ADMIN' && !organizationId) {
      return res.status(403).json({
        error: 'Organization required',
        message: 'Admin users must belong to an organization workspace'
      });
    }

    const sites = await prisma.site.findMany({
      where: organizationId ? { organizationId } : undefined,
      orderBy: { createdAt: 'desc' },
      select: siteSelect
    });

    return res.status(200).json({
      count: sites.length,
      sites
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/:siteId', async (req, res, next) => {
  try {
    const site = await prisma.site.findFirst({
      where: getSiteAccessWhere(req, req.params.siteId),
      select: siteSelect
    });

    if (!site) {
      return handleSiteNotFound(res);
    }

    return res.status(200).json({ site });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:siteId', async (req, res, next) => {
  try {
    const existingSite = await prisma.site.findFirst({
      where: getSiteAccessWhere(req, req.params.siteId),
      select: { id: true }
    });

    if (!existingSite) {
      return handleSiteNotFound(res);
    }

    const name = req.body.name?.trim();
    const address = req.body.address === null ? null : req.body.address?.trim();
    const timezone = req.body.timezone?.trim();
    const active = getOptionalBoolean(req.body.active);
    const data = {};

    if (name !== undefined) {
      if (!name) {
        return res.status(400).json({
          error: 'Validation failed',
          message: 'name cannot be empty'
        });
      }

      data.name = name;
    }

    if (address !== undefined) {
      data.address = address || null;
    }

    if (timezone !== undefined) {
      if (!timezone) {
        return res.status(400).json({
          error: 'Validation failed',
          message: 'timezone cannot be empty'
        });
      }

      data.timezone = timezone;
    }

    if (active !== undefined) {
      data.active = active;
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'Provide at least one field to update'
      });
    }

    const site = await prisma.site.update({
      where: { id: existingSite.id },
      data,
      select: siteSelect
    });

    return res.status(200).json({
      message: 'Site updated',
      site
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
