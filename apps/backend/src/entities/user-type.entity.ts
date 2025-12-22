import { Column, DataType, Table } from "sequelize-typescript";
import { BaseEntity } from "./base.entity";

@Table({
  tableName: 'user_type',
})
export class UserTypeEntity extends BaseEntity {
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare name: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare code: string;

  @Column({
    type: DataType.STRING,
    allowNull: true,
  })
  declare description: string;

  @Column({
    type: DataType.BOOLEAN,
    allowNull: false,
    defaultValue: true,
  })
  declare is_active: boolean;
}