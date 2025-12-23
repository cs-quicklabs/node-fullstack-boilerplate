import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class VerifyEmailDto {
  @ApiProperty({ description: 'Email verification token' })
  @IsString()
  @IsNotEmpty({ message: 'Verification token is required' })
  token: string;
}

export class VerifyEmailByCodeDto {
  @ApiProperty({ description: 'Email verification code (6 digits)' })
  @IsString()
  @IsNotEmpty({ message: 'Verification code is required' })
  code: string;
}

export class ResendVerificationDto {
  @ApiPropertyOptional({ description: 'User email (optional if authenticated)' })
  @IsString()
  @IsOptional()
  email?: string;
}

