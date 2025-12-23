import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { Op } from 'sequelize';
import { UserTypeEntity } from '@src/entities';
import { CreateUserTypeDto, UpdateUserTypeDto } from './dtos';

export interface PaginatedResult<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    hasNextPage: boolean;
    hasPrevPage: boolean;
  };
}

export interface FindAllOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'ASC' | 'DESC';
  where?: Record<string, unknown>;
}

@Injectable()
export class UserTypeService {
  constructor(
    @InjectModel(UserTypeEntity)
    private userTypeModel: typeof UserTypeEntity,
  ) {}

  async findAll(options: FindAllOptions = {}): Promise<PaginatedResult<UserTypeEntity>> {
    const {
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'DESC',
      where = {},
    } = options;

    const safeLimit = Math.min(Math.max(1, limit), 100);
    const safePage = Math.max(1, page);
    const offset = (safePage - 1) * safeLimit;

    const { count, rows } = await this.userTypeModel.findAndCountAll({
      where: {
        ...where,
      },
      order: [[sortBy, sortOrder]],
      limit: safeLimit,
      offset,
    });

    const totalPages = Math.ceil(count / safeLimit);

    return {
      data: rows,
      meta: {
        total: count,
        page: safePage,
        limit: safeLimit,
        totalPages,
        hasNextPage: safePage < totalPages,
        hasPrevPage: safePage > 1,
      },
    };
  }

  async findAllActive(): Promise<UserTypeEntity[]> {
    return this.userTypeModel.findAll({
      where: { is_active: true },
      order: [['name', 'ASC']],
    });
  }

  async findOne(id: number): Promise<UserTypeEntity | null> {
    return this.userTypeModel.findByPk(id);
  }

  async findByCode(code: string): Promise<UserTypeEntity | null> {
    return this.userTypeModel.findOne({
      where: { code: code.toUpperCase() },
    });
  }

  async create(dto: CreateUserTypeDto): Promise<UserTypeEntity> {
    // Check if code already exists
    const existingUserType = await this.userTypeModel.findOne({
      where: { code: dto.code.toUpperCase() },
    });

    if (existingUserType) {
      throw new ConflictException(`User type with code "${dto.code}" already exists`);
    }

    const userType = await this.userTypeModel.create({
      name: dto.name,
      code: dto.code.toUpperCase(),
      description: dto.description || null,
      is_active: dto.isActive !== undefined ? dto.isActive : true,
    });

    return userType;
  }

  async update(id: number, dto: UpdateUserTypeDto): Promise<UserTypeEntity> {
    const userType = await this.userTypeModel.findByPk(id);

    if (!userType) {
      throw new NotFoundException('User type not found');
    }

    const updateData: Partial<UserTypeEntity> = {};

    if (dto.name !== undefined) updateData.name = dto.name;
    if (dto.description !== undefined) updateData.description = dto.description;
    if (dto.isActive !== undefined) updateData.is_active = dto.isActive;

    await userType.update(updateData);

    return userType;
  }

  async delete(id: number): Promise<boolean> {
    const userType = await this.userTypeModel.findByPk(id);

    if (!userType) {
      throw new NotFoundException('User type not found');
    }

    // Don't allow deleting system user types
    const systemCodes = ['SUPER_ADMIN', 'ADMIN', 'USER'];
    if (systemCodes.includes(userType.code)) {
      throw new ConflictException('Cannot delete system user types');
    }

    await userType.destroy();

    return true;
  }

  async toggleActive(id: number): Promise<UserTypeEntity> {
    const userType = await this.userTypeModel.findByPk(id);

    if (!userType) {
      throw new NotFoundException('User type not found');
    }

    // Don't allow deactivating system user types
    const systemCodes = ['SUPER_ADMIN', 'ADMIN', 'USER'];
    if (systemCodes.includes(userType.code) && userType.is_active) {
      throw new ConflictException('Cannot deactivate system user types');
    }

    await userType.update({ is_active: !userType.is_active });

    return userType;
  }

  async searchUserTypes(
    searchQuery: string,
    options: FindAllOptions = {},
  ): Promise<PaginatedResult<UserTypeEntity>> {
    const searchCondition = {
      [Op.or]: [
        { name: { [Op.iLike]: `%${searchQuery}%` } },
        { code: { [Op.iLike]: `%${searchQuery}%` } },
        { description: { [Op.iLike]: `%${searchQuery}%` } },
      ],
    };

    return this.findAll({
      ...options,
      where: {
        ...options.where,
        ...searchCondition,
      },
    });
  }
}

