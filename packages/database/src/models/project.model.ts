import mongoose, { Schema, type Document, type Types } from 'mongoose';

export interface IProjectDocument extends Document {
  name: string;
  description: string;
  ownerId: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const ProjectSchema = new Schema<IProjectDocument>(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: '', trim: true },
    ownerId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  },
  { timestamps: true },
);

export const ProjectModel = mongoose.model<IProjectDocument>('Project', ProjectSchema);
