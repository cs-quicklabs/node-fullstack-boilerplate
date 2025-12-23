import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';
import { Public } from '@src/modules/auth/decorators';
import { SuccessResponse } from '@src/commons/dtos';

@ApiTags('App')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get()
  @ApiOperation({ summary: 'API health check' })
  @ApiResponse({ status: 200, description: 'API is running' })
  getData() {
    return new SuccessResponse('API is running', this.appService.getData());
  }

  @Public()
  @Get('health')
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  healthCheck() {
    return new SuccessResponse('Service is healthy', {
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  }
}
