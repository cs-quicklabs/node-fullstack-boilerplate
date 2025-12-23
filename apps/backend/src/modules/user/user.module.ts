import { Module } from '@nestjs/common';
import { SequelizeModule } from '@nestjs/sequelize';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { UserEntity, UserTypeEntity, OrganizationEntity } from '@src/entities';

@Module({
  imports: [
    SequelizeModule.forFeature([UserEntity, UserTypeEntity, OrganizationEntity]),
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}

