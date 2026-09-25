export interface IProject {
  id: string;
  name: string;
  description: string;
  ownerId: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateProject {
  name: string;
  description?: string;
}

export interface IUpdateProject {
  name?: string;
  description?: string;
}
