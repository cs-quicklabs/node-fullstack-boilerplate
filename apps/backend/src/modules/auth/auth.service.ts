import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/sequelize';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { AllConfigType } from '@src/config/config.type';
import {
  UserEntity,
  UserTypeEntity,
  OrganizationEntity,
  SessionEntity,
  PasswordResetEntity,
} from '@src/entities';
import { EmailService } from '@src/commons/services';
import {
  RegisterDto,
  LoginDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
} from './dtos';
import { JwtPayload, JwtTokens } from './interfaces';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private configService: ConfigService<AllConfigType>,
    @InjectModel(UserEntity)
    private userModel: typeof UserEntity,
    @InjectModel(UserTypeEntity)
    private userTypeModel: typeof UserTypeEntity,
    @InjectModel(OrganizationEntity)
    private organizationModel: typeof OrganizationEntity,
    @InjectModel(SessionEntity)
    private sessionModel: typeof SessionEntity,
    @InjectModel(PasswordResetEntity)
    private passwordResetModel: typeof PasswordResetEntity,
    private emailService: EmailService,
  ) {}

  async register(dto: RegisterDto, ipAddress?: string, userAgent?: string) {
    // Check if email already exists
    const existingUser = await this.userModel.findOne({
      where: { email: dto.email.toLowerCase(), deleted_at: null },
    });

    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Verify organization exists
    const organization = await this.organizationModel.findByPk(dto.organizationId);
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }

    // Get default user type or use provided one
    let userTypeId = dto.userTypeId;
    if (!userTypeId) {
      const defaultUserType = await this.userTypeModel.findOne({
        where: { code: 'USER', is_active: true },
      });
      if (!defaultUserType) {
        throw new NotFoundException('Default user type not found');
      }
      userTypeId = defaultUserType.id;
    }

    // Hash password
    const saltRounds = this.configService.getOrThrow('auth.bcryptSaltRounds', {
      infer: true,
    });
    const hashedPassword = await bcrypt.hash(dto.password, saltRounds);

    // Create user
    const user = await this.userModel.create({
      first_name: dto.firstName,
      last_name: dto.lastName,
      email: dto.email.toLowerCase(),
      phone: dto.phone || null,
      password: hashedPassword,
      organization_id: dto.organizationId,
      user_type_id: userTypeId,
    });

    // Send welcome email
    await this.emailService.sendWelcomeEmail(user.email, {
      name: user.first_name,
    });

    // Generate tokens and create session
    const tokens = await this.createSession(user, ipAddress, userAgent);

    // Fetch user with relations
    const userWithRelations = await this.userModel.findByPk(user.id, {
      include: [UserTypeEntity, OrganizationEntity],
      attributes: { exclude: ['password'] },
    });

    return {
      user: userWithRelations,
      ...tokens,
    };
  }

  async login(dto: LoginDto, ipAddress?: string, userAgent?: string) {
    // Find user
    const user = await this.userModel.findOne({
      where: { email: dto.email.toLowerCase(), deleted_at: null },
      include: [UserTypeEntity, OrganizationEntity],
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(dto.password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Generate tokens and create session
    const tokens = await this.createSession(user, ipAddress, userAgent);

    // Return user without password
    const userResponse = user.toJSON() as Record<string, unknown>;
    delete userResponse.password;

    return {
      user: userResponse,
      ...tokens,
    };
  }

  async refreshToken(refreshToken: string, ipAddress?: string, userAgent?: string) {
    try {
      const jwtSecret = this.configService.getOrThrow('auth.jwtSecret', {
        infer: true,
      });

      const payload = jwt.verify(refreshToken, jwtSecret) as JwtPayload;

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Find the session
      const session = await this.sessionModel.findOne({
        where: {
          id: payload.sessionId,
          user_id: payload.sub,
          refresh_token: refreshToken,
          is_active: true,
        },
      });

      if (!session) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (session.isRefreshTokenExpired) {
        // Revoke the session
        await session.update({ is_active: false, revoked_at: new Date() });
        throw new UnauthorizedException('Refresh token has expired');
      }

      // Get user
      const user = await this.userModel.findByPk(payload.sub, {
        include: [UserTypeEntity],
      });

      if (!user || user.deleted_at) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new tokens
      const tokens = this.generateTokens(user, session.id);

      // Update session with new tokens
      await session.update({
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        access_token_expires_at: tokens.accessTokenExpiresAt,
        refresh_token_expires_at: tokens.refreshTokenExpiresAt,
        ip_address: ipAddress || session.ip_address,
        user_agent: userAgent || session.user_agent,
        last_activity_at: new Date(),
      });

      return tokens;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new UnauthorizedException('Refresh token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw error;
    }
  }

  async logout(sessionId: number) {
    const session = await this.sessionModel.findByPk(sessionId);
    if (session) {
      await session.update({
        is_active: false,
        revoked_at: new Date(),
      });
    }
    return { success: true };
  }

  async logoutAll(userId: number) {
    await this.sessionModel.update(
      { is_active: false, revoked_at: new Date() },
      { where: { user_id: userId, is_active: true } },
    );
    return { success: true };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.userModel.findOne({
      where: { email: dto.email.toLowerCase(), deleted_at: null },
    });

    console.log(user);

    // Always return success to prevent email enumeration
    if (!user) {
      return { success: true, message: 'If the email exists, a reset link has been sent' };
    }

    // Invalidate existing password reset tokens
    await this.passwordResetModel.update(
      { is_used: true },
      { where: { user_id: user.id, is_used: false } },
    );

    // Create new reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const passwordResetExpiresIn = this.configService.getOrThrow(
      'auth.passwordResetExpiresIn',
      { infer: true },
    );

    await this.passwordResetModel.create({
      user_id: user.id,
      token: resetToken,
      expires_at: new Date(Date.now() + passwordResetExpiresIn * 1000),
    });

    // Send reset email
    const frontendDomain = this.configService.getOrThrow('app.frontendDomain', {
      infer: true,
    });
    const resetLink = `${frontendDomain}/reset-password?token=${resetToken}`;
    const expiresInHours = Math.round(passwordResetExpiresIn / 3600);

    await this.emailService.sendPasswordResetEmail(user.email, {
      name: user.first_name,
      resetLink,
      expiresIn: `${expiresInHours} hour${expiresInHours > 1 ? 's' : ''}`,
    });

    return { success: true, message: 'If the email exists, a reset link has been sent' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const passwordReset = await this.passwordResetModel.findOne({
      where: { token: dto.token, is_used: false },
      include: [UserEntity],
    });

    if (!passwordReset) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (passwordReset.isExpired) {
      await passwordReset.update({ is_used: true });
      throw new BadRequestException('Reset token has expired');
    }

    // Hash new password
    const saltRounds = this.configService.getOrThrow('auth.bcryptSaltRounds', {
      infer: true,
    });
    const hashedPassword = await bcrypt.hash(dto.newPassword, saltRounds);

    // Update password
    await this.userModel.update(
      { password: hashedPassword },
      { where: { id: passwordReset.user_id } },
    );

    // Mark token as used
    await passwordReset.update({ is_used: true, used_at: new Date() });

    // Revoke all sessions for security
    await this.sessionModel.update(
      { is_active: false, revoked_at: new Date() },
      { where: { user_id: passwordReset.user_id, is_active: true } },
    );

    return { success: true, message: 'Password reset successfully' };
  }

  async changePassword(userId: number, dto: ChangePasswordDto) {
    const user = await this.userModel.findByPk(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(dto.currentPassword, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash new password
    const saltRounds = this.configService.getOrThrow('auth.bcryptSaltRounds', {
      infer: true,
    });
    const hashedPassword = await bcrypt.hash(dto.newPassword, saltRounds);

    // Update password
    await user.update({ password: hashedPassword });

    return { success: true, message: 'Password changed successfully' };
  }

  async getActiveSessions(userId: number) {
    const sessions = await this.sessionModel.findAll({
      where: {
        user_id: userId,
        is_active: true,
        revoked_at: null,
      },
      attributes: ['id', 'uuid', 'ip_address', 'user_agent', 'device_type', 'last_activity_at', 'createdAt'],
      order: [['last_activity_at', 'DESC']],
    });

    return sessions;
  }

  async revokeSession(userId: number, sessionId: number) {
    const session = await this.sessionModel.findOne({
      where: { id: sessionId, user_id: userId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    await session.update({ is_active: false, revoked_at: new Date() });

    return { success: true, message: 'Session revoked successfully' };
  }

  // Private helper methods
  private async createSession(
    user: UserEntity,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<JwtTokens> {
    // Create session first with placeholder tokens
    const session = await this.sessionModel.create({
      user_id: user.id,
      access_token: 'placeholder',
      refresh_token: 'placeholder',
      access_token_expires_at: new Date(),
      refresh_token_expires_at: new Date(),
      ip_address: ipAddress || null,
      user_agent: userAgent || null,
      device_type: this.parseDeviceType(userAgent),
      last_activity_at: new Date(),
    });

    // Generate tokens with session ID
    const tokens = this.generateTokens(user, session.id);

    // Update session with actual tokens
    await session.update({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      access_token_expires_at: tokens.accessTokenExpiresAt,
      refresh_token_expires_at: tokens.refreshTokenExpiresAt,
    });

    return tokens;
  }

  private generateTokens(user: UserEntity, sessionId: number): JwtTokens {
    const jwtSecret = this.configService.getOrThrow('auth.jwtSecret', {
      infer: true,
    });
    const accessTokenExpiresIn = this.configService.getOrThrow(
      'auth.jwtAccessTokenExpiresIn',
      { infer: true },
    );
    const refreshTokenExpiresIn = this.configService.getOrThrow(
      'auth.jwtRefreshTokenExpiresIn',
      { infer: true },
    );

    const accessTokenPayload: JwtPayload = {
      sub: user.id,
      uuid: user.uuid,
      email: user.email,
      organizationId: user.organization_id,
      userTypeCode: user.user_type?.code || '',
      sessionId,
      type: 'access',
    };

    const refreshTokenPayload: JwtPayload = {
      sub: user.id,
      uuid: user.uuid,
      email: user.email,
      organizationId: user.organization_id,
      userTypeCode: user.user_type?.code || '',
      sessionId,
      type: 'refresh',
    };

    const accessToken = jwt.sign(accessTokenPayload, jwtSecret, {
      expiresIn: accessTokenExpiresIn,
    });

    const refreshToken = jwt.sign(refreshTokenPayload, jwtSecret, {
      expiresIn: refreshTokenExpiresIn,
    });

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: new Date(Date.now() + accessTokenExpiresIn * 1000),
      refreshTokenExpiresAt: new Date(Date.now() + refreshTokenExpiresIn * 1000),
    };
  }

  private parseDeviceType(userAgent?: string): string | null {
    if (!userAgent) return null;
    
    const ua = userAgent.toLowerCase();
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
      return 'mobile';
    }
    if (ua.includes('tablet') || ua.includes('ipad')) {
      return 'tablet';
    }
    return 'desktop';
  }
}
