import { instanceToPlain } from 'class-transformer';
import { Column, CreatedAt, DataType, Model, UpdatedAt } from 'sequelize-typescript';
import { Sequelize } from 'sequelize';

// these columns will be presented in all the entity
// this will be extended.
export abstract class BaseEntity extends Model<Record<string, unknown>> {
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  declare id: number;

  @CreatedAt
  @Column({ 
    field: 'created_at', 
    type: DataType.DATE,
    allowNull: false, 
    defaultValue: Sequelize.literal('NOW()')
  })
  declare createdAt: Date;

  @UpdatedAt
  @Column({ 
    field: 'updated_at', 
    type: DataType.DATE,
    allowNull: false, 
    defaultValue: Sequelize.literal('NOW()')
  })
  declare updatedAt: Date;

  override toJSON() {
    return instanceToPlain(this);
  }
}
