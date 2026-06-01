import cors from 'cors';
import express from 'express';
import { errorHandler, notFound } from './middleware/errorHandler.js';
import adminRoutes from './routes/admins.routes.js';
import authRoutes from './routes/auth.routes.js';
import departmentRoutes from './routes/departments.routes.js';
import jobRoleRoutes from './routes/jobRoles.routes.js';
import organizationRoutes from './routes/organizations.routes.js';
import siteRoutes from './routes/sites.routes.js';
import workerRoutes from './routes/workers.routes.js';

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/admins', adminRoutes);
app.use('/api/organizations', organizationRoutes);
app.use('/api/sites', siteRoutes);
app.use('/api/departments', departmentRoutes);
app.use('/api/job-roles', jobRoleRoutes);
app.use('/api/workers', workerRoutes);

app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'workforce-scheduler-api'
  });
});

app.use(notFound);
app.use(errorHandler);

export default app;
