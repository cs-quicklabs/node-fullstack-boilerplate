import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import * as jwt from 'jsonwebtoken';
import { InjectModel } from '@nestjs/sequelize';
import { IS_PUBLIC_KEY } from '../decorators';
import { JwtPayload, CurrentUser } from '../interfaces';
import { SessionEntity, UserEntity, UserTypeEntity } from '@src/entities';
import { AllConfigType } from '@src/config/config.type';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private configService: ConfigService<AllConfigType>,
    @InjectModel(SessionEntity)
    private sessionModel: typeof SessionEntity,
    @InjectModel(UserEntity)
    private userModel: typeof UserEntity,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Access token is required');
    }

    try {
      const jwtSecret = this.configService.getOrThrow('auth.jwtSecret', {
        infer: true,
      });

      const payload = jwt.verify(token, jwtSecret) as JwtPayload;

      // Verify this is an access token
      if (payload.type !== 'access') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Verify session exists and is valid
      const session = await this.sessionModel.findOne({
        where: {
          id: payload.sessionId,
          user_id: payload.sub,
          is_active: true,
        },
      });

      if (!session) {
        throw new UnauthorizedException('Session not found or has been revoked');
      }

      if (session.isAccessTokenExpired) {
        throw new UnauthorizedException('Access token has expired');
      }

      if (session.revoked_at) {
        throw new UnauthorizedException('Session has been revoked');
      }

      // Get user with user type
      const user = await this.userModel.findOne({
        where: { id: payload.sub },
        include: [{ model: UserTypeEntity }],
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (user.deleted_at) {
        throw new UnauthorizedException('User account has been deactivated');
      }

      // Update last activity
      await session.update({ last_activity_at: new Date() });

      // Attach user to request
      const currentUser: CurrentUser = {
        id: user.id,
        uuid: user.uuid,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        organizationId: user.organization_id,
        userTypeId: user.user_type_id,
        userTypeCode: user.user_type?.code || '',
        sessionId: session.id,
      };

      (request as Request & { user: CurrentUser }).user = currentUser;

      return true;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new UnauthorizedException('Access token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new UnauthorizedException('Invalid access token');
      }
      throw error;
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}

