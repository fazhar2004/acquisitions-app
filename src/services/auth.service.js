import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error('Error while hashing password', e);
    throw e;
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (e) {
    logger.error('Error while comparing password', e);
    throw e;
  }
};

export const authenticateUser = async ({ email, password }) => {
  try {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!user) throw new Error('Invalid credentials');

    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) throw new Error('Invalid credentials');

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      created_at: user.created_at,
      updated_at: user.updated_at,
    };
  } catch (e) {
    logger.error('Error authenticating user', e);
    throw e;
  }
};

// createUser function accepts an object {} // more secure
export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0) throw new Error('User with this email already exists');

    // hashing password
    const hashed_password = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, role, password: hashed_password })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });

    logger.info(`User ${newUser.email}is created successfully`);
    return newUser; // final

  } catch (e) {
    logger.error('Error creating the user');
    throw e;
  }
};
