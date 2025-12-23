import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app/app.controller';
import { AppService } from './app/app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import appConfig from './config/app.config';
import databaseConfig from './database/config/database.config';
import authConfig from './config/auth.config';
import mailerConfig from './config/mailer.config';
import smsConfig from './config/sms.config';
import { SequelizeModule } from '@nestjs/sequelize';
import { SequelizeConfigService } from './database/sequelize-config.service';
import { MailerModule } from '@boilerplate/mailer';
import { SmsModule } from '@boilerplate/sms';
import { AllConfigType } from './config/config.type';
import { EmailService } from './commons/services';

// Modules
import { AuthModule, JwtAuthGuard } from './modules/auth';
import { UserModule } from './modules/user';
import { OrganizationModule } from './modules/organization';
import { UserTypeModule } from './modules/user-type';

// Entities for guards
import { SequelizeModule as SequelizeFeatureModule } from '@nestjs/sequelize';
import { SessionEntity, UserEntity } from './entities';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      load: [appConfig, databaseConfig, authConfig, mailerConfig, smsConfig],
      isGlobal: true,
    }),
    
    // Database
    SequelizeModule.forRootAsync({
      useClass: SequelizeConfigService,
    }),
    
    // Register entities for global guards
    SequelizeFeatureModule.forFeature([SessionEntity, UserEntity]),
    
    // Mailer Package (only for sending)
    MailerModule.forRootAsync({
      isGlobal: true,
      useFactory: (configService: ConfigService<AllConfigType>) => {
        const mailerCfg = configService.getOrThrow('mailer', { infer: true });
        return {
          host: mailerCfg.host,
          port: mailerCfg.port,
          secure: mailerCfg.secure,
          auth: {
            user: mailerCfg.user,
            pass: mailerCfg.pass,
          },
          defaultFrom: mailerCfg.defaultFrom,
          previewEmail: mailerCfg.previewEmail,
        };
      },
      inject: [ConfigService],
    }),
    
    // SMS Package (only for sending)
    SmsModule.forRootAsync({
      isGlobal: true,
      useFactory: (configService: ConfigService<AllConfigType>) => {
        const smsCfg = configService.getOrThrow('sms', { infer: true });
        return {
          accountSid: smsCfg.accountSid,
          authToken: smsCfg.authToken,
          fromNumber: smsCfg.fromNumber,
          previewMode: smsCfg.previewMode,
        };
      },
      inject: [ConfigService],
    }),
    
    // Feature Modules
    AuthModule,
    UserModule,
    OrganizationModule,
    UserTypeModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    EmailService,
    // Global JWT Auth Guard - protects all routes by default
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
  exports: [EmailService],
})
export class AppModule {}
