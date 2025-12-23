import { QueryInterface, DataTypes } from 'sequelize';

/**
 * Initial seed migration to create default user types and an initial organization
 */
export async function up(queryInterface: QueryInterface): Promise<void> {
  const now = new Date();

  // Create user_type table if not exists
  await queryInterface.createTable('user_type', {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    code: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    description: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: now,
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: now,
    },
  });

  // Insert default user types
  await queryInterface.bulkInsert('user_type', [
    {
      name: 'Super Administrator',
      code: 'SUPER_ADMIN',
      description: 'Full system access across all organizations',
      is_active: true,
      created_at: now,
      updated_at: now,
    },
    {
      name: 'Administrator',
      code: 'ADMIN',
      description: 'Organization administrator with full access to organization resources',
      is_active: true,
      created_at: now,
      updated_at: now,
    },
    {
      name: 'Standard User',
      code: 'USER',
      description: 'Standard user with basic access',
      is_active: true,
      created_at: now,
      updated_at: now,
    },
  ]);

  // Create organization table if not exists
  await queryInterface.createTable('organization', {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    uuid: {
      type: DataTypes.UUID,
      allowNull: false,
      defaultValue: DataTypes.UUIDV4,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    image: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    address: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    phone: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    website: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    description: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    deleted_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: now,
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: now,
    },
  });

  // Insert default organization
  await queryInterface.bulkInsert('organization', [
    {
      uuid: '00000000-0000-0000-0000-000000000001',
      name: 'Default Organization',
      description: 'Initial organization for the platform',
      created_at: now,
      updated_at: now,
    },
  ]);
}

export async function down(queryInterface: QueryInterface): Promise<void> {
  await queryInterface.bulkDelete('organization', {});
  await queryInterface.bulkDelete('user_type', {});
  await queryInterface.dropTable('organization');
  await queryInterface.dropTable('user_type');
}

