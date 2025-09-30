import { prisma } from './db';
import bcrypt from 'bcrypt';      


async function up(email: string, pass: string) {
  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return;

  const passwordHash = await bcrypt.hash(pass, 12);
  await prisma.user.create({
    data: { email, passwordHash, role: 'ADMIN' },
  });
  console.log('Admin creado:', email);
}

(async () => {
  await up('mayita@tu-dominio.com', 'EurekaGuanare.1');
  await up('admin2@tu-dominio.com', 'ClaveFuerte#2');
  process.exit(0);
})();