// prisma/seed.ts
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log(`Iniciando el seeding...`);

  const passwordEureka = await bcrypt.hash('EurekaGuanare.1', 12);
  const passwordClave = await bcrypt.hash('ClaveFuerte#2', 12);

  // Usuario 1
  await prisma.user.upsert({
    where: { email: 'mayita@tu-dominio.com' },
    update: {},
    create: {
      email: 'mayita@tu-dominio.com',
      passwordHash: passwordEureka,
      role: 'ADMIN',
    },
  });
  console.log('Usuario admin "mayita@tu-dominio.com" creado o actualizado.');

  // Usuario 2
  await prisma.user.upsert({
    where: { email: 'admin2@tu-dominio.com' },
    update: {},
    create: {
      email: 'admin2@tu-dominio.com',
      passwordHash: passwordClave,
      role: 'ADMIN',
    },
  });
  console.log('Usuario admin "admin2@tu-dominio.com" creado o actualizado.');

  console.log(`Seeding finalizado.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });