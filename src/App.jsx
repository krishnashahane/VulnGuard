import { lazy, Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';

const DynamicScan = lazy(() => import('./pages/DynamicScan'));
const StaticScan = lazy(() => import('./pages/StaticScan'));
const Report = lazy(() => import('./pages/Report'));
const NotFound = lazy(() => import('./pages/NotFound'));

function App() {
  return (
    <Layout>
      <Suspense fallback={<div className="min-h-[60dvh]" />}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/dynamic" element={<DynamicScan />} />
          <Route path="/scan/static" element={<StaticScan />} />
          <Route path="/report/:id" element={<Report />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </Layout>
  );
}

export default App;
