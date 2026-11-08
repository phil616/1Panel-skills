import { setupLocal } from './setup-local.mjs';
import { runMatrix } from './run.mjs';
let env;
try {
  env = await setupLocal();
  console.log('Disposable 1Panel and OpenResty ready');
  const report = await runMatrix(env.config);
  console.log(
    JSON.stringify({ status: report.status, passed: report.passed, failed: report.failed }),
  );
} catch (err) {
  console.error(err.code || err.name, err.message, err.details || '');
  process.exitCode = 1;
} finally {
  if (env) {
    await env.cleanup();
    console.log('Disposable containers, network, DB, certificates and journal removed');
  }
}
