import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../utils/prisma.js';

const router = Router();

const departmentSelect = {
  id: true,
  siteId: true,
  name: true,
  description: true,
  active: true,
  createdAt: true,
  updatedAt: true,
  site: {
    select: {
      id: true,
      name: true,
      organizationId: true
    }
  }
};

function getOptionalBoolean(value) {
  return typeof value === 'boolean' ? value : undefined;
}

function handleDepartmentNotFound(res) {
  return res.status(404).json({
    error: 'Department not found',
    message: 'No department exists with the provided departmentId'
  });
}

async function ensureSiteExists(siteId, res) {
  const site = await prisma.site.findUnique({
    where: { id: siteId },
    select: { id: true }
  });

  if (!site) {
    res.status(404).json({
      error: 'Site not found',
      message: 'No site exists with the provided siteId'
    });
    return false;
  }

  return true;
}

router.use(requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'));

router.post('/', async (req, res, next) => {
  try {
    const siteId = req.body.siteId?.trim();
    const name = req.body.name?.trim();
    const description = req.body.description?.trim() || null;
    const active = getOptionalBoolean(req.body.active);

    if (!siteId || !name) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'siteId and name are required'
      });
    }

    if (!(await ensureSiteExists(siteId, res))) {
      return;
    }

    const department = await prisma.department.create({
      data: {
        siteId,
        name,
        description,
        ...(active !== undefined ? { active } : {})
      },
      select: departmentSelect
    });

    return res.status(201).json({
      message: 'Department created',
      department
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const siteId = req.query.siteId?.toString().trim();

    const departments = await prisma.department.findMany({
      where: siteId ? { siteId } : undefined,
      orderBy: { createdAt: 'desc' },
      select: departmentSelect
    });

    return res.status(200).json({
      count: departments.length,
      departments
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:departmentId', async (req, res, next) => {
  try {
    const department = await prisma.department.findUnique({
      where: { id: req.params.departmentId },
      select: { id: true }
    });

    if (!department) {
      return handleDepartmentNotFound(res);
    }

    const siteId = req.body.siteId?.trim();
    const name = req.body.name?.trim();
    const description = req.body.description === null ? null : req.body.description?.trim();
    const active = getOptionalBoolean(req.body.active);
    const data = {};

    if (siteId !== undefined) {
      if (!siteId) {
        return res.status(400).json({
          error: 'Validation failed',
          message: 'siteId cannot be empty'
        });
      }

      if (!(await ensureSiteExists(siteId, res))) {
        return;
      }

      data.siteId = siteId;
    }

    if (name !== undefined) {
      if (!name) {
        return res.status(400).json({
          error: 'Validation failed',
          message: 'name cannot be empty'
        });
      }

      data.name = name;
    }

    if (description !== undefined) {
      data.description = description || null;
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

    const updatedDepartment = await prisma.department.update({
      where: { id: req.params.departmentId },
      data,
      select: departmentSelect
    });

    return res.status(200).json({
      message: 'Department updated',
      department: updatedDepartment
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
