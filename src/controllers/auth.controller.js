import logger from '#config/logger.js';
import { formatValidationError } from '#utils/auth.format.js';
import { signUpSchema, signInSchema } from '#validations/auth.validation.js';
import { createUser, authenticateUser } from '#services/auth.service.js';
import { jwttoken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation Failed',
        details: formatValidationError(validationResult.error),
      });
    }

    // Destructring of Data to gain acces (safer when passing into functions)
    const { name, email, password, role } = validationResult.data;

    // AUTH SERVICE
    const user = await createUser({name, email, password, role});

    // token
    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User sucessfully registered ${email}`);
    res.status(201).json({
      message: 'User successfully created',
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
    
  } catch (e) {
    logger.error('SignUp Error', e);

    if (e.message === 'User with this email already exists') {
      return res.status(409).json({ error: 'Email already exist' });
    }

    next(e);
  }
};

export const signin = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation Failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { email, password } = validationResult.data;

    const user = await authenticateUser({ email, password });

    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User successfully signed in ${email}`);
    res.status(200).json({
      message: 'User successfully signed in',
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (e) {
    logger.error('SignIn Error', e);

    if (e.message === 'Invalid credentials') {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    next(e);
  }
};

export const signout = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User successfully signed out');
    res.status(200).json({ message: 'User successfully signed out' });
  } catch (e) {
    logger.error('SignOut Error', e);
    next(e);
  }
};
