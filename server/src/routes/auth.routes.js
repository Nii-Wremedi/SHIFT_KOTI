import bcrypt from 'bcrypt';
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../utils/prisma.js';

const router = Router();
const SALT_ROUNDS = 12;

function splitFullName(fullName) {
  const parts = fullName.trim().split(/\s+/);
  const firstName = parts.shift();
  const lastName = parts.join(' ') || firstName;

  return { firstName, lastName };
}

function getJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  return process.env.JWT_SECRET;
}

function sanitizeUser(user) {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    role: user.role,
    isActive: user.isActive,
    organizationId: user.organizationId,
    organization: user.organization
      ? {
          id: user.organization.id,
          name: user.organization.name,
          industryType: user.organization.industryType,
          status: user.organization.status
        }
      : null,
    worker: user.workerAccount
      ? {
          id: user.workerAccount.id,
          fullName: user.workerAccount.fullName,
          staffId: user.workerAccount.staffId,
          phone: user.workerAccount.phone,
          status: user.workerAccount.status
        }
      : null
  };
}

function validateRegistration(body) {
  const fullName = body.fullName?.trim();
  const email = body.email?.trim().toLowerCase();
  const password = body.password;
  const phone = body.phone?.trim() || null;
  const staffId = body.staffId?.trim() || null;
  const organizationInviteCode = body.organizationInviteCode?.trim().toUpperCase();

  if (!fullName || !email || !password || !organizationInviteCode) {
    return {
      error: 'Validation failed',
      message: 'fullName, email, password, and organizationInviteCode are required'
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
      fullName,
      email,
      password,
      phone,
      staffId,
      organizationInviteCode
    }
  };
}

function getUniqueConflictMessage(error) {
  const target = Array.isArray(error.meta?.target) ? error.meta.target.join(', ') : error.meta?.target;

  if (target?.includes('email')) {
    return 'An account with this email already exists';
  }

  if (target?.includes('staffId')) {
    return 'A worker with this staffId already exists';
  }

  return 'A record with one of these unique values already exists';
}

router.post('/register-worker', async (req, res, next) => {
  try {
    const validation = validateRegistration(req.body);

    if (validation.error) {
      return res.status(400).json(validation);
    }

    const { fullName, email, password, phone, staffId, organizationInviteCode } = validation.data;
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const { firstName, lastName } = splitFullName(fullName);

    const organization = await prisma.organization.findUnique({
      where: { inviteCode: organizationInviteCode },
      select: {
        id: true,
        name: true,
        industryType: true,
        status: true,
        active: true
      }
    });

    if (!organization) {
      return res.status(404).json({
        error: 'Organization not found',
        message: 'No organization exists with the provided invite code'
      });
    }

    if (!organization.active || organization.status !== 'ACTIVE') {
      return res.status(403).json({
        error: 'Organization unavailable',
        message: 'This organization is not active for worker registration'
      });
    }

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

    if (staffId) {
      const existingWorker = await prisma.worker.findUnique({
        where: { staffId },
        select: { id: true }
      });

      if (existingWorker) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'A worker with this staffId already exists'
        });
      }
    }

    const user = await prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
        data: {
          organizationId: organization.id,
          email,
          passwordHash,
          firstName,
          lastName,
          role: 'WORKER'
        }
      });

      const createdWorker = await tx.worker.create({
        data: {
          organizationId: organization.id,
          userId: createdUser.id,
          fullName,
          phone,
          staffId,
          status: 'PENDING'
        }
      });

      return {
        ...createdUser,
        organization,
        workerAccount: createdWorker
      };
    });

    return res.status(201).json({
      message: 'Worker registration submitted for approval',
      user: sanitizeUser(user)
    });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({
        error: 'Conflict',
        message: getUniqueConflictMessage(error)
      });
    }

    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'email and password are required'
      });
    }

    const user = await prisma.user.findUnique({
      where: { email },
      include: {
        workerAccount: true,
        organization: {
          select: {
            id: true,
            name: true,
            industryType: true,
            status: true,
            active: true
          }
        }
      }
    });

    if (!user) {
      return res.status(401).json({
        error: 'Login failed',
        message: 'Invalid email or password'
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        error: 'Account disabled',
        message: 'This account has been deactivated'
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
      return res.status(401).json({
        error: 'Login failed',
        message: 'Invalid email or password'
      });
    }

    const token = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId,
        workerId: user.workerAccount?.id || null
      },
      getJwtSecret(),
      { expiresIn: '1d' }
    );

    return res.status(200).json({
      token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
