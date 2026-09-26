import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { UserModel } from '@securityscan/database';
import { z } from 'zod';
import { validate } from '../middleware/validate.js';
import { authRateLimiter } from '../middleware/rate-limiter.js';

const JWT_SECRET = process.env['JWT_SECRET'] ?? 'change-me-in-production';
const JWT_EXPIRES_IN = (process.env['JWT_EXPIRES_IN'] ?? '24h') as any;

export const authRouter = Router();

const RegisterSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(200),
  password: z.string().min(8).max(128),
});

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

authRouter.post('/register', authRateLimiter, validate(RegisterSchema), async (req, res, next) => {
  try {
    const { email, name, password } = req.body;
    const existing = await UserModel.findOne({ email });
    if (existing) {
      res.status(409).json({ error: { code: 'CONFLICT', message: 'Email already registered' } });
      return;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await UserModel.create({ email, name, passwordHash });
    const token = jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });
    res.status(201).json({
      user: { id: user._id, email: user.email, name: user.name, role: user.role },
      token,
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/login', authRateLimiter, validate(LoginSchema), async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email });
    if (!user) {
      res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } });
      return;
    }
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } });
      return;
    }
    const token = jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });
    res.json({
      user: { id: user._id, email: user.email, name: user.name, role: user.role },
      token,
    });
  } catch (err) {
    next(err);
  }
});
