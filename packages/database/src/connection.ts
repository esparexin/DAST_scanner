import mongoose from 'mongoose';

let isConnected = false;

export async function connectDatabase(uri?: string): Promise<void> {
  if (isConnected) return;
  const mongoUri = uri ?? process.env['MONGODB_URI'] ?? 'mongodb://localhost:27017/securityscan';
  await mongoose.connect(mongoUri);
  isConnected = true;
}

export async function disconnectDatabase(): Promise<void> {
  if (!isConnected) return;
  await mongoose.disconnect();
  isConnected = false;
}
