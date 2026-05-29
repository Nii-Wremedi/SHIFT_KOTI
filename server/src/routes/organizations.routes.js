import bcrypt from 'bcrypt';
import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import prisma from '../utils/prisma.js';

const router = Router();
const SALT_ROUNDS = 12;

const organizationSelect = {
  id: true,
  name: true,
  industryType: true,
  status: true,
  inviteCode: true,
  contactEmail: true,
  contactPhone: true,
  registrationNumber: true,
  address: true,
  active: true,
  approvedAt: true,
  approvedBy: true,
  createdAt: true,
  updatedAt: true
};

function getOptionalBoolean(value) {
  return typeof value === 'boolean' ? value : undefined;
}

function handleOrganizationNotFound(res) {
  return res.status(404).json({
    error: 'Organization not found',
    message: 'No organization exists with the provided organizationId'
  });
}

function generateInviteCodeValue() {
  return `ORG-${randomBytes(4).toString('hex').toUpperCase()}`;
}

async function generateUniqueInviteCode(tx = prisma) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const inviteCode = generateInviteCodeValue();
    const existingOrganization = await tx.organization.findUnique({
      where: { inviteCode },
      select: { id: true }
    });

    if (!existingOrganization) {
      return inviteCode;
    }
  }

  throw new Error('Unable to generate a unique organization invite code');
}

function validateOrganizationRegistration(body) {
  const organizationName = body.organizationName?.trim();
  const industryType = body.industryType?.trim() || null;
  const contactEmail = body.contactEmail?.trim().toLowerCase();
  const contactPhone = body.contactPhone?.trim() || null;
  const address = body.address?.trim() || null;
  const registrationNumber = body.registrationNumber?.trim() || null;
  const adminFirstName = body.adminFirstName?.trim();
  const adminLastName = body.adminLastName?.trim();
  const adminEmail = body.adminEmail?.trim().toLowerCase();
  const adminPassword = body.adminPassword;

  if (!organizationName || !contactEmail || !adminFirstName || !adminLastName || !adminEmail || !adminPassword) {
    return {
      error: 'Validation failed',
      message:
        'organizationName, contactEmail, adminFirstName, adminLastName, adminEmail, and adminPassword are required'
    };
  }

  if (adminPassword.length < 8) {
    return {
      error: 'Validation failed',
      message: 'Admin password must be at least 8 characters long'
    };
  }

  return {
    data: {
      organizationName,
      industryType,
      contactEmail,
      contactPhone,
      address,
      registrationNumber,
      adminFirstName,
      adminLastName,
      adminEmail,
      adminPassword
    }
  };
}

function sanitizeAdmin(user) {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    role: user.role,
    isActive: user.isActive,
    organizationId: user.organizationId
  };
}

router.post('/register', async (req, res, next) => {
  try {
    const validation = validateOrganizationRegistration(req.body);

    if (validation.error) {
      return res.status(400).json(validation);
    }

    const {
      organizationName,
      industryType,
      contactEmail,
      contactPhone,
      address,
      registrationNumber,
      adminFirstName,
      adminLastName,
      adminEmail,
      adminPassword
    } = validation.data;

    const existingAdmin = await prisma.user.findUnique({
      where: { email: adminEmail },
      select: { id: true }
    });

    if (existingAdmin) {
      return res.status(409).json({
        error: 'Conflict',
        message: 'An account with this admin email already exists'
      });
    }

    const passwordHash = await bcrypt.hash(adminPassword, SALT_ROUNDS);

    const result = await prisma.$transaction(async (tx) => {
      const inviteCode = await generateUniqueInviteCode(tx);

      const organization = await tx.organization.create({
        data: {
          name: organizationName,
          industryType,
          inviteCode,
          contactEmail,
          contactPhone,
          address,
          registrationNumber,
          status: 'PENDING',
          active: true
        },
        select: organizationSelect
      });

      const admin = await tx.user.create({
        data: {
          organizationId: organization.id,
          email: adminEmail,
          passwordHash,
          firstName: adminFirstName,
          lastName: adminLastName,
          role: 'ADMIN',
          isActive: false
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isActive: true,
          organizationId: true
        }
      });

      return { organization, admin };
    });

    return res.status(201).json({
      message: 'Organization registration submitted for approval',
      organization: result.organization,
      admin: sanitizeAdmin(result.admin)
    });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({
        error: 'Conflict',
        message: 'An organization or account with unique values already exists'
      });
    }

    return next(error);
  }
});

router.get('/public', async (req, res, next) => {
  try {
    const organizations = await prisma.organization.findMany({
      where: {
        status: 'ACTIVE',
        active: true
      },
      orderBy: { name: 'asc' },
      select: {
        id: true,
        name: true,
        industryType: true
      }
    });

    return res.status(200).json({
      count: organizations.length,
      organizations
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/by-invite/:inviteCode', async (req, res, next) => {
  try {
    const inviteCode = req.params.inviteCode.trim().toUpperCase();

    const organization = await prisma.organization.findUnique({
      where: { inviteCode },
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

    return res.status(200).json({ organization });
  } catch (error) {
    return next(error);
  }
});

router.use(requireAuth);

router.patch('/:organizationId/approve', requireRole('SUPER_ADMIN'), async (req, res, next) => {
  try {
    const organization = await prisma.organization.findUnique({
      where: { id: req.params.organizationId },
      select: { id: true }
    });

    if (!organization) {
      return handleOrganizationNotFound(res);
    }

    const result = await prisma.$transaction(async (tx) => {
      const updatedOrganization = await tx.organization.update({
        where: { id: req.params.organizationId },
        data: {
          status: 'ACTIVE',
          active: true,
          approvedAt: new Date(),
          approvedBy: req.user.sub
        },
        select: organizationSelect
      });

      await tx.user.updateMany({
        where: {
          organizationId: req.params.organizationId,
          role: 'ADMIN'
        },
        data: { isActive: true }
      });

      const admins = await tx.user.findMany({
        where: {
          organizationId: req.params.organizationId,
          role: 'ADMIN'
        },
        orderBy: { createdAt: 'asc' },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          isActive: true,
          organizationId: true
        }
      });

      return { organization: updatedOrganization, admins };
    });

    return res.status(200).json({
      message: 'Organization approved',
      organization: result.organization,
      admins: result.admins.map(sanitizeAdmin)
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:organizationId/suspend', requireRole('SUPER_ADMIN'), async (req, res, next) => {
  try {
    const organization = await prisma.organization.findUnique({
      where: { id: req.params.organizationId },
      select: { id: true }
    });

    if (!organization) {
      return handleOrganizationNotFound(res);
    }

    const result = await prisma.$transaction(async (tx) => {
      const updatedOrganization = await tx.organization.update({
        where: { id: req.params.organizationId },
        data: {
          status: 'SUSPENDED',
          active: false
        },
        select: organizationSelect
      });

      await tx.user.updateMany({
        where: { organizationId: req.params.organizationId },
        data: { isActive: false }
      });

      return updatedOrganization;
    });

    return res.status(200).json({
      message: 'Organization suspended',
      organization: result
    });
  } catch (error) {
    return next(error);
  }
});

router.use(requireRole('SUPER_ADMIN', 'ADMIN'));

router.post('/', async (req, res, next) => {
  try {
    const name = req.body.name?.trim();
    const industryType = req.body.industryType?.trim() || null;
    const contactEmail = req.body.contactEmail?.trim().toLowerCase() || null;
    const contactPhone = req.body.contactPhone?.trim() || null;
    const registrationNumber = req.body.registrationNumber?.trim() || null;
    const address = req.body.address?.trim() || null;
    const active = getOptionalBoolean(req.body.active);

    if (!name) {
      return res.status(400).json({
        error: 'Validation failed',
        message: 'name is required'
      });
    }

    const inviteCode = await generateUniqueInviteCode();

    const organization = await prisma.organization.create({
      data: {
        name,
        industryType,
        inviteCode,
        contactEmail,
        contactPhone,
        registrationNumber,
        address,
        status: 'PENDING',
        ...(active !== undefined ? { active } : {})
      },
      select: organizationSelect
    });

    return res.status(201).json({
      message: 'Organization created',
      organization
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const organizations = await prisma.organization.findMany({
      orderBy: { createdAt: 'desc' },
      select: organizationSelect
    });

    return res.status(200).json({
      count: organizations.length,
      organizations
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/:organizationId', async (req, res, next) => {
  try {
    const organization = await prisma.organization.findUnique({
      where: { id: req.params.organizationId },
      select: { id: true }
    });

    if (!organization) {
      return handleOrganizationNotFound(res);
    }

    const name = req.body.name?.trim();
    const industryType = req.body.industryType === null ? null : req.body.industryType?.trim();
    const contactEmail = req.body.contactEmail === null ? null : req.body.contactEmail?.trim().toLowerCase();
    const contactPhone = req.body.contactPhone === null ? null : req.body.contactPhone?.trim();
    const registrationNumber =
      req.body.registrationNumber === null ? null : req.body.registrationNumber?.trim();
    const address = req.body.address === null ? null : req.body.address?.trim();
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

    if (industryType !== undefined) {
      data.industryType = industryType || null;
    }

    if (contactEmail !== undefined) {
      data.contactEmail = contactEmail || null;
    }

    if (contactPhone !== undefined) {
      data.contactPhone = contactPhone || null;
    }

    if (registrationNumber !== undefined) {
      data.registrationNumber = registrationNumber || null;
    }

    if (address !== undefined) {
      data.address = address || null;
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

    const updatedOrganization = await prisma.organization.update({
      where: { id: req.params.organizationId },
      data,
      select: organizationSelect
    });

    return res.status(200).json({
      message: 'Organization updated',
      organization: updatedOrganization
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
