import { instanceToPlain } from 'class-transformer';
import { Column, DataType, Model } from 'sequelize-typescript';

// these columns will be presented in all the entity
// this will be extended.
export abstract class BaseEntity extends Model<Record<string, unknown>> {
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  declare id: number;

  @Column({
    type: DataType.DATE,
    allowNull: false,
    defaultValue: DataType.NOW,
  })
  declare created_at: Date;

  @Column({
    type: DataType.DATE,
    allowNull: false,
    defaultValue: DataType.NOW,
  })
  declare updated_at: Date;

  override toJSON() {
    return instanceToPlain(this);
  }
}
