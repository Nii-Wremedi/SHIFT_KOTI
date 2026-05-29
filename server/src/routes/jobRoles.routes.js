import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../utils/prisma.js';

const router = Router();

const jobRoleSelect = {
  id: true,
  departmentId: true,
  title: true,
  description: true,
  active: true,
  createdAt: true,
  updatedAt: true,
  department: {
    select: {
      id: true,
      name: true,
      siteId: true
    }
  }
};

function getOptionalBoolean(value) {
  return typeof value === 'boolean' ? value : undefined;
}

function handleJobRoleNotFound(res) {
  return res.status(404).json({
    error: 'Job role not found',
    message: 'No job role exists with the provided jobRoleId'
  });
}

async function ensureDepartmentExists(departmentId, res) {
  const department = await prisma.department.findUnique({
    where: { id: departmentId },
    select: { id: true }
  });

  if (!department) {
    res.status(404).json({
      error: 'Department not found',
      message: 'No department exists with the provided departmentId'
    });
    return false;
  }

  return true;
}

router.use(requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'));

router.post('/', async (req, res, next) => {
  try {
    const departmentId = req.body.departmentId?.trim();
    const title = req.body.title?.trim();
    const description = req.body.description?.trim() || null;
    const active = getOptionalBoolean(req.body.active);

    if (!departmentId || !title) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'departmentId and title are required'
      });
    }

    if (!(await ensureDepartmentExists(departmentId, res))) {
      return;
    }

    const jobRole = await prisma.jobRole.create({
      data: {
        departmentId,
        title,
        description,
        ...(active !== undefined ? { active } : {})
      },
      select: jobRoleSelect
    });

    return res.status(201).json({
      message: 'Job role created',
      jobRole
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const departmentId = req.query.departmentId?.toString().trim();

    const jobRoles = await prisma.jobRole.findMany({
      where: departmentId ? { departmentId } : undefined,
      orderBy: { createdAt: 'desc' },
      select: jobRoleSelect
    });

    return res.status(200).json({
      count: jobRoles.length,
      jobRoles
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:jobRoleId', async (req, res, next) => {
  try {
    const jobRole = await prisma.jobRole.findUnique({
      where: { id: req.params.jobRoleId },
      select: { id: true }
    });

    if (!jobRole) {
      return handleJobRoleNotFound(res);
    }

    const departmentId = req.body.departmentId?.trim();
    const title = req.body.title?.trim();
    const description = req.body.description === null ? null : req.body.description?.trim();
    const active = getOptionalBoolean(req.body.active);
    const data = {};

    if (departmentId !== undefined) {
      if (!departmentId) {
        return res.status(400).json({
          error: 'Validation failed',
          message: 'departmentId cannot be empty'
        });
      }

      if (!(await ensureDepartmentExists(departmentId, res))) {
        return;
      }

      data.departmentId = departmentId;
    }

    if (title !== undefined) {
      if (!title) {
        return res.status(400).json({
          error: 'Validation failed',
          message: 'title cannot be empty'
        });
      }

      data.title = title;
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

    const updatedJobRole = await prisma.jobRole.update({
      where: { id: req.params.jobRoleId },
      data,
      select: jobRoleSelect
    });

    return res.status(200).json({
      message: 'Job role updated',
      jobRole: updatedJobRole
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
