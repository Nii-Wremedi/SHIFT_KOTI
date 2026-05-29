import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import prisma from '../utils/prisma.js';

const SALT_ROUNDS = 12;
const __dirname = dirname(fileURLToPath(import.meta.url));

dotenv.config({ path: resolve(__dirname, '../../../.env') });
dotenv.config({ path: resolve(__dirname, '../../.env') });

function getRequiredEnv(name) {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

async function main() {
  const email = getRequiredEnv('SUPER_ADMIN_EMAIL').toLowerCase();
  const password = getRequiredEnv('SUPER_ADMIN_PASSWORD');
  const firstName = getRequiredEnv('SUPER_ADMIN_FIRST_NAME');
  const lastName = getRequiredEnv('SUPER_ADMIN_LAST_NAME');

  const existingUser = await prisma.user.findUnique({
    where: { email },
    select: { id: true, role: true }
  });

  if (existingUser) {
    console.log(`Super admin seed skipped. User already exists for ${email}.`);
    return;
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const superAdmin = await prisma.user.create({
    data: {
      email,
      passwordHash,
      firstName,
      lastName,
      role: 'SUPER_ADMIN',
      isActive: true
    },
    select: {
      id: true,
      email: true,
      role: true,
      isActive: true
    }
  });

  console.log(`Super admin created: ${superAdmin.email} (${superAdmin.id})`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
