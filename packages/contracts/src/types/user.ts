export interface IUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'user';
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateUser {
  email: string;
  name: string;
  password: string;
}

export interface ILoginCredentials {
  email: string;
  password: string;
}
