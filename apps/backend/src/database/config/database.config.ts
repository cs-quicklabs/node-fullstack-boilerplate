import { registerAs } from '@nestjs/config';
import {
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { DatabaseConfig } from './database-config.type';
import { validateConfig } from '@src/commons/utils';

class EnvironmentVariablesValidator {
  @IsOptional()
  @IsString()
  DATABASE_TYPE: 'postgres' | 'mysql' | 'sqlite' | 'mariadb' | 'mssql';

  @IsString()
  DATABASE_HOST: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(65535)
  DATABASE_PORT: number;

  @IsString()
  DATABASE_NAME: string;

  @IsString()
  DATABASE_USERNAME: string;

  @IsString()
  DATABASE_PASSWORD: string;

  @IsBoolean()
  @IsOptional()
  DATABASE_LOG: string;
}

export default registerAs<DatabaseConfig>('database', () => {
  validateConfig(process.env, EnvironmentVariablesValidator);

  return {
    dialect: process.env.DATABASE_TYPE ?? 'postgres',
    host: process.env.DATABASE_HOST,
    port: process.env.DATABASE_PORT ? parseInt(process.env.DATABASE_PORT, 10) : 5432,
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME,
    logging: process.env.DATABASE_LOG === 'true',
  };
});
