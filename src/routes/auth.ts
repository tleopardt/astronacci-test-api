import { Router, Request, Response } from 'express';
import { db } from '../db';
import mysql, { ResultSetHeader, RowDataPacket } from 'mysql2';
import multer from 'multer';
import path from 'path';
import dayjs from 'dayjs';
import * as jwt from 'jsonwebtoken';
import bcrypt from "bcrypt";
import { AuthRequest, verifyToken } from '../middleware';

const router = Router();

const storage = multer.diskStorage({
  destination: './uploads',
  
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);

    cb(null, Date.now() + ext);
  }
});

const upload = multer({ storage });

const CREATED_AT = dayjs().format('YYYY-MM-DD HH:mm:ss');

// ================ Start Routing ==================

router.post('/register', async (req: Request, res: Response) => {
  const { first_name, last_name, birth_date, email, phone, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  if (!first_name || !email || !password) {
    return res.status(400).json({
      error: 'first_name, email, and password are required.'
    });
  }

  const checkQuery = `SELECT * FROM user_info WHERE email = ${mysql.escape(email)}`;

  db.query(checkQuery, (err, results: RowDataPacket[]) => {
    if (err) {
      return res.status(500).json({ error: 'Database error', message: err.message });
    }

    if (results.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const query = `
      INSERT INTO user_info 
        (first_name, last_name, birth_date, email, phone, password, created_at) 
      VALUES (
        ${mysql.escape(first_name)},
        ${mysql.escape(last_name)},
        ${mysql.escape(birth_date)},
        ${mysql.escape(email)},
        ${mysql.escape(phone)},
        ${mysql.escape(hashedPassword)},
        ${mysql.escape(CREATED_AT)}
      )`;

    db.query(query, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Insert failed', message: err.message });
      }

      return res.status(201).json({ message: 'User successfully registered' });
    });    
  });
});

router.post('/upload_profile_image', upload.single('dir_image'), verifyToken, (req: AuthRequest, res: Response) => {
  // Get id from the authenticated user (JWT token)
  const user = req.user as { id: number; email: string };
  const id = user?.id;

  const dir_image = req.file;
  
  if (!id || !dir_image) {
    return res.status(400).json({ error: 'Missing user authentication or image' });
  }
  
  const imagePath = `/uploads/${dir_image.filename}`;
  const sql = `UPDATE user_info SET dir_image = ${mysql.escape(imagePath)} WHERE id = ${mysql.escape(id)}`;
  
  db.query(sql, (err, result: ResultSetHeader) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Failed to update image path' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.status(201).json({ 
      message: 'Profile image successfully updated',
      imagePath: imagePath
    });
  });
});

router.post('/edit_profile', (req: Request, res: Response) => {
    const { id, first_name, last_name, birth_date, phone } = req.body;

    const query = `UPDATE user_info SET 
        first_name = ${mysql.escape(first_name)}, 
        last_name = ${mysql.escape(last_name)}, 
        birth_date = ${mysql.escape(birth_date)}, 
        phone = ${mysql.escape(phone)}, 
        updated_at = ${mysql.escape(CREATED_AT)} 
        WHERE id = ${id}`;

    db.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Update failed', message: err.message });
        }

        return res.status(201).json({ 
          message: 'User info successfully updated',
          auth: {
              username: `${first_name.trim()} ${last_name.trim()}`
          }
        });
    });
});

router.get('/list_user', verifyToken, (req: Request, res: Response) => {
    const query = `SELECT * FROM user_info`;

    db.query(query, (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Error API', message: err.message });
        }

        return res.status(201).json(result);
    });
});

router.post('/detail_user', verifyToken, (req: Request, res: Response) => {
    const { id } = req.body;

    const query = `SELECT first_name, last_name, birth_date, email, phone, dir_image 
        FROM user_info WHERE id = ${mysql.escape(id)}`;

    db.query(query, (err, result: RowDataPacket[]) => {
        if (err) {
            return res.status(500).json({ error: 'Error API', message: err.message });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        return res.status(201).json(result[0]);
    });
});

router.post('/login', (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    const query = `SELECT * FROM user_info WHERE email = ${mysql.escape(email)}`;

    db.query(query, async (err, results) => {
        const users = results as RowDataPacket[];

        if (err) {
            return res.status(500).json({ error: 'Database error', message: err.message });
        }

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        
        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Generate JWT
        const token = await jwt.sign(
            { 
                id: user.id, 
                email: user.email 
            },
            process.env.JWT_SECRET as jwt.Secret,
            {
                algorithm: 'HS256',
                expiresIn: '1h'
            }
        );

        // Delete any existing session for this user
        const deleteHistorySession = `DELETE FROM user_session WHERE email = ${mysql.escape(user.email)}`;
        
        db.query(deleteHistorySession, () => {
            // Saving session to database
            let tokenExpires: string | null = null;
            const decodedToken = jwt.decode(token) as jwt.JwtPayload;

            if (decodedToken && typeof decodedToken.exp === 'number') {
                tokenExpires = dayjs(decodedToken.exp * 1000).format('YYYY-MM-DD HH:mm:ss');
            }

            const saveSession = `INSERT INTO user_session 
                (email, token, created_at, expires_at) 
                VALUES (${mysql.escape(user.email)}, ${mysql.escape(token)}, ${mysql.escape(CREATED_AT)}, ${mysql.escape(tokenExpires)})`;
            
            db.query(saveSession, () => {
                return res.status(200).json({
                    message: 'Login successful',
                    auth: {
                        user_id: user.id,
                        token: token,
                        email: user.email,
                        username: `${user.first_name} ${user.last_name}`,
                    }
                });
            });
        });
    });
});

router.post('/logout', verifyToken, (req: AuthRequest, res: Response) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Credential is expired' });
    }

    const token = authHeader.split(' ')[1];

    const deleteQuery = `DELETE FROM user_session WHERE token = ${mysql.escape(token)}`;

    db.query(deleteQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout', message: err.message });
        }

        return res.status(200).json({ message: 'Successfully logged out' });
    });
});


export default router;
