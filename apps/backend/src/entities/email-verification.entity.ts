import { BelongsTo, Column, DataType, ForeignKey, Index, IsUUID, Table } from 'sequelize-typescript';
import { Sequelize } from 'sequelize';
import { BaseEntity } from './base.entity';
import { UserEntity } from './user.entity';

@Table({
  tableName: 'email_verification',
})
export class EmailVerificationEntity extends BaseEntity {
  @IsUUID(4)
  @Index({ name: 'IDX_EMAIL_VERIFICATION_UUID', unique: true })
  @Column({
    type: DataType.UUID,
    allowNull: false,
    defaultValue: Sequelize.literal('gen_random_uuid()'),
  })
  declare uuid: string;

  @ForeignKey(() => UserEntity)
  @Column({
    type: DataType.INTEGER,
    allowNull: false,
  })
  declare user_id: number;

  @BelongsTo(() => UserEntity)
  declare user: UserEntity;

  @Index({ name: 'IDX_EMAIL_VERIFICATION_TOKEN' })
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare token: string;

  @Column({
    type: DataType.STRING,
    allowNull: true,
  })
  declare code: string | null;

  @Column({
    type: DataType.DATE,
    allowNull: false,
  })
  declare expires_at: Date;

  @Column({
    type: DataType.BOOLEAN,
    allowNull: false,
    defaultValue: false,
  })
  declare is_verified: boolean;

  @Column({
    type: DataType.DATE,
    allowNull: true,
  })
  declare verified_at: Date | null;

  get isExpired(): boolean {
    return new Date() > this.expires_at;
  }
}

