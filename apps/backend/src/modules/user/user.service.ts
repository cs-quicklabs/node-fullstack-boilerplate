import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { Op } from 'sequelize';
import { BaseCrudService, FindAllOptions, PaginatedResult } from '@src/commons/base';
import { UserEntity, UserTypeEntity, OrganizationEntity } from '@src/entities';
import { AllConfigType } from '@src/config/config.type';
import { CreateUserDto, UpdateUserDto } from './dtos';

@Injectable()
export class UserService extends BaseCrudService<UserEntity, CreateUserDto, UpdateUserDto> {
  protected readonly model = UserEntity;
  protected readonly entityName = 'User';

  constructor(
    @InjectModel(UserEntity)
    private userModel: typeof UserEntity,
    @InjectModel(UserTypeEntity)
    private userTypeModel: typeof UserTypeEntity,
    @InjectModel(OrganizationEntity)
    private organizationModel: typeof OrganizationEntity,
    private configService: ConfigService<AllConfigType>,
  ) {
    super();
  }

  async findAll(options: FindAllOptions = {}): Promise<PaginatedResult<UserEntity>> {
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

    const { count, rows } = await this.userModel.findAndCountAll({
      where: {
        ...where,
        deleted_at: null,
      },
      include: [
        { model: UserTypeEntity, attributes: ['id', 'name', 'code'] },
        { model: OrganizationEntity, attributes: ['id', 'uuid', 'name'] },
      ],
      attributes: { exclude: ['password'] },
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

  async findOne(id: number): Promise<UserEntity | null> {
    return this.userModel.findOne({
      where: { id, deleted_at: null },
      include: [
        { model: UserTypeEntity, attributes: ['id', 'name', 'code'] },
        { model: OrganizationEntity, attributes: ['id', 'uuid', 'name'] },
      ],
      attributes: { exclude: ['password'] },
    });
  }

  async findByUuid(uuid: string): Promise<UserEntity | null> {
    return this.userModel.findOne({
      where: { uuid, deleted_at: null },
      include: [
        { model: UserTypeEntity, attributes: ['id', 'name', 'code'] },
        { model: OrganizationEntity, attributes: ['id', 'uuid', 'name'] },
      ],
      attributes: { exclude: ['password'] },
    });
  }

  async findByEmail(email: string): Promise<UserEntity | null> {
    return this.userModel.findOne({
      where: { email: email.toLowerCase(), deleted_at: null },
      include: [UserTypeEntity],
    });
  }

  async create(dto: CreateUserDto): Promise<UserEntity> {
    // Check if email already exists
    const existingUser = await this.userModel.findOne({
      where: { email: dto.email.toLowerCase(), deleted_at: null },
    });

    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Verify organization exists
    const organization = await this.organizationModel.findByPk(dto.organizationId);
    if (!organization || organization.deleted_at) {
      throw new NotFoundException('Organization not found');
    }

    // Verify user type exists
    const userType = await this.userTypeModel.findByPk(dto.userTypeId);
    if (!userType || !userType.is_active) {
      throw new NotFoundException('User type not found or inactive');
    }

    // Hash password
    const saltRounds = this.configService.getOrThrow('auth.bcryptSaltRounds', {
      infer: true,
    });
    const hashedPassword = await bcrypt.hash(dto.password, saltRounds);

    const user = await this.userModel.create({
      first_name: dto.firstName,
      last_name: dto.lastName,
      email: dto.email.toLowerCase(),
      phone: dto.phone || null,
      password: hashedPassword,
      gender: dto.gender || null,
      profile_picture: dto.profilePicture || null,
      organization_id: dto.organizationId,
      user_type_id: dto.userTypeId,
    });

    // Fetch user with relations (without password)
    return this.findOne(user.id) as Promise<UserEntity>;
  }

  async update(id: number, dto: UpdateUserDto): Promise<UserEntity> {
    const user = await this.userModel.findOne({
      where: { id, deleted_at: null },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if email is being changed and if it's already taken
    if (dto.email && dto.email.toLowerCase() !== user.email) {
      const existingUser = await this.userModel.findOne({
        where: {
          email: dto.email.toLowerCase(),
          deleted_at: null,
          id: { [Op.ne]: id },
        },
      });

      if (existingUser) {
        throw new ConflictException('Email already registered');
      }
    }

    // Verify user type if being changed
    if (dto.userTypeId) {
      const userType = await this.userTypeModel.findByPk(dto.userTypeId);
      if (!userType || !userType.is_active) {
        throw new NotFoundException('User type not found or inactive');
      }
    }

    const updateData: Partial<UserEntity> = {};

    if (dto.firstName) updateData.first_name = dto.firstName;
    if (dto.lastName) updateData.last_name = dto.lastName;
    if (dto.email) updateData.email = dto.email.toLowerCase();
    if (dto.phone !== undefined) updateData.phone = dto.phone;
    if (dto.gender !== undefined) updateData.gender = dto.gender;
    if (dto.profilePicture !== undefined) updateData.profile_picture = dto.profilePicture;
    if (dto.userTypeId) updateData.user_type_id = dto.userTypeId;

    await user.update(updateData);

    return this.findOne(id) as Promise<UserEntity>;
  }

  async softDelete(id: number): Promise<boolean> {
    const user = await this.userModel.findOne({
      where: { id, deleted_at: null },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await user.update({ deleted_at: new Date() });

    return true;
  }

  async restore(id: number): Promise<UserEntity> {
    const user = await this.userModel.findOne({
      where: { id, deleted_at: { [Op.ne]: null } },
    });

    if (!user) {
      throw new NotFoundException('User not found or not deleted');
    }

    await user.update({ deleted_at: null });

    return this.findOne(id) as Promise<UserEntity>;
  }

  // Multi-tenant methods
  async findAllByOrganization(
    organizationId: number,
    options: FindAllOptions = {},
  ): Promise<PaginatedResult<UserEntity>> {
    return this.findAll({
      ...options,
      where: {
        ...options.where,
        organization_id: organizationId,
      },
    });
  }

  async findOneByOrganization(
    id: number,
    organizationId: number,
  ): Promise<UserEntity | null> {
    return this.userModel.findOne({
      where: { id, organization_id: organizationId, deleted_at: null },
      include: [
        { model: UserTypeEntity, attributes: ['id', 'name', 'code'] },
        { model: OrganizationEntity, attributes: ['id', 'uuid', 'name'] },
      ],
      attributes: { exclude: ['password'] },
    });
  }

  async searchUsers(
    organizationId: number,
    searchQuery: string,
    options: FindAllOptions = {},
  ): Promise<PaginatedResult<UserEntity>> {
    const searchCondition = {
      [Op.or]: [
        { first_name: { [Op.iLike]: `%${searchQuery}%` } },
        { last_name: { [Op.iLike]: `%${searchQuery}%` } },
        { email: { [Op.iLike]: `%${searchQuery}%` } },
      ],
    };

    return this.findAll({
      ...options,
      where: {
        ...options.where,
        organization_id: organizationId,
        ...searchCondition,
      },
    });
  }
}

