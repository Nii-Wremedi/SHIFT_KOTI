import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../utils/prisma.js';

const router = Router();

const WORKER_STATUSES = ['PENDING', 'ACTIVE', 'SUSPENDED'];

const workerSelect = {
  id: true,
  userId: true,
  departmentId: true,
  jobRoleId: true,
  fullName: true,
  staffId: true,
  phone: true,
  status: true,
  approvedAt: true,
  approvedBy: true,
  createdAt: true,
  updatedAt: true,
  user: {
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      role: true,
      isActive: true
    }
  },
  approver: {
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true
    }
  },
  department: {
    select: {
      id: true,
      name: true,
      siteId: true
    }
  },
  jobRole: {
    select: {
      id: true,
      title: true,
      departmentId: true
    }
  }
};

function getAdminUserId(req) {
  return req.user?.sub;
}

function handleWorkerNotFound(res) {
  return res.status(404).json({
    error: 'Worker not found',
    message: 'No worker exists with the provided workerId'
  });
}

router.use(requireAuth, requireRole('SUPER_ADMIN', 'ADMIN'));

router.get('/', async (req, res, next) => {
  try {
    const status = req.query.status?.toString().trim().toUpperCase();

    if (status && !WORKER_STATUSES.includes(status)) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'status must be one of PENDING, ACTIVE, or SUSPENDED'
      });
    }

    const workers = await prisma.worker.findMany({
      where: status ? { status } : undefined,
      orderBy: { createdAt: 'desc' },
      select: workerSelect
    });

    return res.status(200).json({
      count: workers.length,
      workers
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:workerId/approve', async (req, res, next) => {
  try {
    const worker = await prisma.worker.findUnique({
      where: { id: req.params.workerId },
      select: { id: true, userId: true }
    });

    if (!worker) {
      return handleWorkerNotFound(res);
    }

    const updatedWorker = await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: worker.userId },
        data: { isActive: true }
      });

      return tx.worker.update({
        where: { id: req.params.workerId },
        data: {
          status: 'ACTIVE',
          approvedAt: new Date(),
          approvedBy: getAdminUserId(req)
        },
        select: workerSelect
      });
    });

    return res.status(200).json({
      message: 'Worker approved',
      worker: updatedWorker
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:workerId/suspend', async (req, res, next) => {
  try {
    const worker = await prisma.worker.findUnique({
      where: { id: req.params.workerId },
      select: { id: true, userId: true }
    });

    if (!worker) {
      return handleWorkerNotFound(res);
    }

    const updatedWorker = await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: worker.userId },
        data: { isActive: false }
      });

      return tx.worker.update({
        where: { id: req.params.workerId },
        data: {
          status: 'SUSPENDED'
        },
        select: workerSelect
      });
    });

    return res.status(200).json({
      message: 'Worker suspended',
      worker: updatedWorker
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:workerId/reactivate', async (req, res, next) => {
  try {
    const worker = await prisma.worker.findUnique({
      where: { id: req.params.workerId },
      select: { id: true, userId: true }
    });

    if (!worker) {
      return handleWorkerNotFound(res);
    }

    const updatedWorker = await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: worker.userId },
        data: { isActive: true }
      });

      return tx.worker.update({
        where: { id: req.params.workerId },
        data: {
          status: 'ACTIVE'
        },
        select: workerSelect
      });
    });

    return res.status(200).json({
      message: 'Worker reactivated',
      worker: updatedWorker
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
