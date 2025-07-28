import { Request, Response, NextFunction } from 'express';

// Simple in-memory session store for demo purposes
// In production, use redis, database, or express-session with proper store
interface Session {
  id: string;
  userId?: string;
  username?: string;
  createdAt: Date;
  lastAccess: Date;
}

class SessionStore {
  private sessions = new Map<string, Session>();

  create(): string {
    const sessionId = this.generateSessionId();
    const session: Session = {
      id: sessionId,
      createdAt: new Date(),
      lastAccess: new Date(),
    };
    this.sessions.set(sessionId, session);
    return sessionId;
  }

  get(sessionId: string): Session | null {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastAccess = new Date();
      return session;
    }
    return null;
  }

  update(sessionId: string, data: Partial<Session>): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      Object.assign(session, data, { lastAccess: new Date() });
    }
  }

  destroy(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  cleanup(): void {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    this.sessions.forEach((session, id) => {
      if (session.lastAccess < oneHourAgo) {
        this.sessions.delete(id);
      }
    });
  }

  private generateSessionId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }
}

const sessionStore = new SessionStore();

// Cleanup old sessions every 30 minutes
setInterval(() => sessionStore.cleanup(), 30 * 60 * 1000);

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      session?: Session;
      sessionId?: string;
    }
  }
}

export function sessionMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Get session ID from cookie
  let sessionId = req.cookies?.sessionId;

  if (!sessionId) {
    // Create new session
    sessionId = sessionStore.create();
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });
  }

  // Get or create session
  let session = sessionStore.get(sessionId);
  if (!session) {
    // Session expired or invalid, create new one
    sessionId = sessionStore.create();
    session = sessionStore.get(sessionId)!;
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    });
  }

  req.session = session;
  req.sessionId = sessionId;

  // Helper methods
  (req as any).login = (userId: string, username: string) => {
    sessionStore.update(sessionId!, { userId, username });
    req.session!.userId = userId;
    req.session!.username = username;
  };

  (req as any).logout = () => {
    sessionStore.destroy(sessionId!);
    res.clearCookie('sessionId');
    req.session = undefined;
  };

  (req as any).isAuthenticated = () => {
    return req.session?.userId !== undefined;
  };

  next();
}

export { sessionStore };
