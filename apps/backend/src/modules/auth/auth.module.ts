import { Module } from '@nestjs/common';
import { SequelizeModule } from '@nestjs/sequelize';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard, RolesGuard } from './guards';
import { EmailService } from '@src/commons/services';
import {
  UserEntity,
  UserTypeEntity,
  OrganizationEntity,
  SessionEntity,
  PasswordResetEntity,
} from '@src/entities';

@Module({
  imports: [
    SequelizeModule.forFeature([
      UserEntity,
      UserTypeEntity,
      OrganizationEntity,
      SessionEntity,
      PasswordResetEntity,
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtAuthGuard, RolesGuard, EmailService],
  exports: [AuthService, JwtAuthGuard, RolesGuard],
})
export class AuthModule {}
