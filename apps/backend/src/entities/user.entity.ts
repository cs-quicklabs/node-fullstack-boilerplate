import { BelongsTo, Column, DataType, ForeignKey, Table } from "sequelize-typescript";
import { BaseEntity } from "./base.entity";
import { UserTypeEntity } from "./user-type.entity";
import { OrganizationEntity } from "./organization.entity";

@Table({
  tableName: 'user',
})
export class UserEntity extends BaseEntity {
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare first_name: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare last_name: string;

  @Column({
    type: DataType.VIRTUAL,
    allowNull: false,
  })
  get full_name(): string {
    return `${this.first_name} ${this.last_name}`.trim();
  }

  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare email: string;

  @Column({
    type: DataType.STRING,
    allowNull: true,
  })
  declare phone: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare password: string;

  @Column({
    type: DataType.STRING,
    allowNull: true,
  })
  declare gender: 'male' | 'female' | 'other';

  @Column({
    type: DataType.STRING,
    allowNull: true,
  })
  declare profile_picture: string;

  @Column({
    type: DataType.DATE,
    allowNull: true,
  })
  declare deleted_at: Date | null;

  @ForeignKey(() => UserTypeEntity)
  @Column({
    type: DataType.INTEGER,
    allowNull: false,
  })
  declare user_type_id: number;

  @BelongsTo(() => UserTypeEntity)
  declare user_type: UserTypeEntity;

  @ForeignKey(() => OrganizationEntity)
  @Column({
    type: DataType.INTEGER,
    allowNull: false,
  })
  declare organization_id: number;

  @BelongsTo(() => OrganizationEntity)
  declare organization: OrganizationEntity;
}