import bcrypt from 'bcrypt';
import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../utils/prisma.js';

const router = Router();
const SALT_ROUNDS = 12;

const adminSelect = {
  id: true,
  email: true,
  firstName: true,
  lastName: true,
  role: true,
  isActive: true,
  createdAt: true,
  updatedAt: true
};

function validateAdminCreate(body) {
  const firstName = body.firstName?.trim();
  const lastName = body.lastName?.trim();
  const email = body.email?.trim().toLowerCase();
  const password = body.password;

  if (!firstName || !lastName || !email || !password) {
    return {
      error: 'Validation failed',
      message: 'firstName, lastName, email, and password are required'
    };
  }

  if (password.length < 8) {
    return {
      error: 'Validation failed',
      message: 'Password must be at least 8 characters long'
    };
  }

  return {
    data: {
      firstName,
      lastName,
      email,
      password
    }
  };
}

function handleAdminNotFound(res) {
  return res.status(404).json({
    error: 'Admin not found',
    message: 'No admin account exists with the provided userId'
  });
}

async function findAdminUser(userId) {
  return prisma.user.findFirst({
    where: {
      id: userId,
      role: {
        in: ['SUPER_ADMIN', 'ADMIN']
      }
    },
    select: { id: true }
  });
}

router.use(requireAuth, requireRole('SUPER_ADMIN'));

router.post('/', async (req, res, next) => {
  try {
    const validation = validateAdminCreate(req.body);

    if (validation.error) {
      return res.status(400).json(validation);
    }

    const { firstName, lastName, email, password } = validation.data;

    const existingUser = await prisma.user.findUnique({
      where: { email },
      select: { id: true }
    });

    if (existingUser) {
      return res.status(409).json({
        error: 'Conflict',
        message: 'An account with this email already exists'
      });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const admin = await prisma.user.create({
      data: {
        firstName,
        lastName,
        email,
        passwordHash,
        role: 'ADMIN',
        isActive: true
      },
      select: adminSelect
    });

    return res.status(201).json({
      message: 'Admin account created',
      admin
    });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({
        error: 'Conflict',
        message: 'An account with this email already exists'
      });
    }

    return next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const admins = await prisma.user.findMany({
      where: {
        role: {
          in: ['SUPER_ADMIN', 'ADMIN']
        }
      },
      orderBy: { createdAt: 'desc' },
      select: adminSelect
    });

    return res.status(200).json({
      count: admins.length,
      admins
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:userId/deactivate', async (req, res, next) => {
  try {
    const admin = await findAdminUser(req.params.userId);

    if (!admin) {
      return handleAdminNotFound(res);
    }

    const updatedAdmin = await prisma.user.update({
      where: { id: req.params.userId },
      data: { isActive: false },
      select: adminSelect
    });

    return res.status(200).json({
      message: 'Admin account deactivated',
      admin: updatedAdmin
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:userId/reactivate', async (req, res, next) => {
  try {
    const admin = await findAdminUser(req.params.userId);

    if (!admin) {
      return handleAdminNotFound(res);
    }

    const updatedAdmin = await prisma.user.update({
      where: { id: req.params.userId },
      data: { isActive: true },
      select: adminSelect
    });

    return res.status(200).json({
      message: 'Admin account reactivated',
      admin: updatedAdmin
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
