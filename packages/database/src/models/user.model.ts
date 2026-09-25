import mongoose, { Schema, type Document } from 'mongoose';

export interface IUserDocument extends Document {
  email: string;
  name: string;
  passwordHash: string;
  role: 'admin' | 'user';
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema = new Schema<IUserDocument>(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    name: { type: String, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
  },
  { timestamps: true },
);

UserSchema.index({ email: 1 });

export const UserModel = mongoose.model<IUserDocument>('User', UserSchema);
