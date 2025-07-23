import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import mysql, { RowDataPacket } from 'mysql2';
import { db } from '../db';

export interface AuthRequest extends Request {
  user?: JwtPayload | string;
}

export const verifyToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided', message: authHeader });
  }

  const token = authHeader.split(' ')[1];

  const query = `SELECT * from user_session WHERE token = ${mysql.escape(token)}`;

  db.query(query, (err, result: RowDataPacket[]) => {
    if (err) {
        return res.status(500).json({ error: 'Error API', message: err.message });
    }

    if (result.length === 0) {
      return res.status(401).json({ error: 'Token is invalid or expired' });
      
    } else {
      try {
        const secret = process.env.JWT_SECRET as string;
        const decoded = jwt.verify(token, secret);

        req.user = decoded;
        
        next();

      } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });

      }
    }
  });

};
