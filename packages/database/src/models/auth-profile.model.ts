import mongoose, { Schema, type Document, type Types } from 'mongoose';
import { AuthType, AuthProfileRole } from '@securityscan/contracts';

export interface IAuthProfileDocument extends Document {
  projectId: Types.ObjectId;
  name: string;
  role: AuthProfileRole;
  type: AuthType;
  /** Encrypted JSON string of auth configuration */
  encryptedConfiguration: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const AuthProfileSchema = new Schema<IAuthProfileDocument>(
  {
    projectId: { type: Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    name: { type: String, required: true, trim: true },
    role: { type: String, enum: Object.values(AuthProfileRole), default: AuthProfileRole.USER },
    type: { type: String, enum: Object.values(AuthType), required: true },
    encryptedConfiguration: { type: String, required: true },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true },
);

export const AuthProfileModel = mongoose.model<IAuthProfileDocument>('AuthProfile', AuthProfileSchema);
