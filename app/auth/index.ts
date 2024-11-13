import { serialize } from 'cookie';
import { addDays, addMinutes } from 'date-fns';
import jwt from 'jsonwebtoken';
import { ulid } from 'ulid';
import bcrypt from 'bcryptjs';
import { db } from '~/db';
import { parse } from 'cookie';
import { redirect } from '@remix-run/node';

type TToken = {
  tokenId: string;
  userId: string;
};

const generateAccessToken = (data: TToken) =>
  jwt.sign(data, process.env.COOKIE_JWT_SECRET, {
    expiresIn: '30min',
  });

const generateRefreshToken = (data: TToken) =>
  jwt.sign(data, process.env.COOKIE_JWT_SECRET, {
    expiresIn: '30d',
  });

export const getUserFromRequest = async (request: Request) => {
  const cookies = parse(request.headers.get('Cookie') ?? '');
  const at = verifyToken(cookies['at']);
  if (at) {
    return await db.userTable.findUniqueOrThrow({
      where: { id: at.userId },
      include: { Org: true },
    });
  } else {
    const rt = verifyToken(cookies['rt']);
    if (rt) {
      return await db.userTable.findUniqueOrThrow({
        where: { id: rt.userId },
        include: { Org: true },
      });
    } else {
      return null;
    }
  }
};

export const verifyToken = (
  token: string | undefined | null,
): TToken | null => {
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.COOKIE_JWT_SECRET as string, {
      algorithms: ['HS256'],
    });
  } catch (error) {
    console.error(token, 'Token verification failed:', error);
    return null;
  }
};

export const revokeOldRefreshToken = async (tokenId: string) => {
  console.log('revokeOldRefreshToken');
  try {
    await db.refreshTokenTable.update({
      where: { id: tokenId },
      data: { status: 'REVOKED' },
    });
  } catch (e) {
    throw redirect('/logout');
  }
};

export const createNewTokens = async (userId: string, familyId?: string) => {
  console.log('createNewTokens');

  const tokenId = ulid();
  const accessToken = generateAccessToken({ tokenId, userId });
  const refreshToken = generateRefreshToken({ tokenId, userId });

  await db.refreshTokenTable.create({
    data: {
      id: tokenId,
      userId,
      createdAt: new Date(),
      expiresAt: addDays(new Date(), 30),
      familyId: familyId || tokenId,
      token: refreshToken,
      status: 'GRANTED',
    },
  });

  return { accessToken, refreshToken };
};

export const createHeaderCookies = (
  accessToken: string,
  refreshToken: string,
) => {
  console.log('createHeaderCookies');
  const headers = new Headers();
  headers.append(
    'Set-Cookie',
    serialize('at', accessToken, {
      path: '/',
      sameSite: 'lax',
      domain: process.env.COOKIE_DOMAIN,
      expires: accessToken ? addMinutes(new Date(), 30) : new Date(0),
    }),
  );
  headers.append(
    'Set-Cookie',
    serialize('rt', refreshToken, {
      path: '/',
      sameSite: 'lax',
      domain: process.env.COOKIE_DOMAIN,
      expires: refreshToken ? addDays(new Date(), 30) : new Date(0),
    }),
  );
  return headers;
};

export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  try {
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    console.error('Error hashing password:', error);
    throw new Error('Hashing failed');
  }
}
