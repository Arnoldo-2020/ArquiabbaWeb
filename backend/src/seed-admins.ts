import { prisma } from './db';          
import bcrypt from 'bcryptjs';          

type UserCreate = Parameters<typeof prisma.user.create>[0]['data'];

async function up(email: string, pass: string) {
  const passwordHash = await bcrypt.hash(pass, 12);

  
  const data: UserCreate = {
    email,
    passwordHash,
  } as any;

  await prisma.user.upsert({
    where: { email },
    update: {}, 
    create: data,
  });

  console.log('Admin OK:', email);
}

(async () => {
  await up('mayita@tu-dominio.com', 'EurekaGuanare.1');
  await up('admin2@tu-dominio.com', 'ClaveFuerte#2');
  process.exit(0);
})();