const bodyParser = require('body-parser');
const crypto = require('crypto');

/**
 * This is the entry point for your Probot App.
 * @param {import('probot').Application} app - Probot's Application class.
 */
module.exports = app => {
  app.log('Yay, the app was loaded!');

  /**
   * @type {Map<string, number>}
   */
  let orgInstalls = null;

  async function loadOrgInstallations(force = false) {
    if (orgInstalls && !force) {
      return;
    }

    const github = await app.auth();
    await github.paginate(github.apps.listInstallations.endpoint.merge({ per_page: 100 }),
      async res => {
        orgInstalls = new Map(res.data.map(installation => [installation.account.login, installation.id]));
      });
  }

  // Hard-load installations map when installations are added/removed
  app.on('installation', () => loadOrgInstallations(true));
  app.on('check_run.rerequested', async context => {
    await context.github.repos.createCommitComment({
      ...context.repo(),
      commit_sha: context.payload.check_run.head_sha,
      body: 'Sorry, checks cannot be re-requested in Checkers. Try re-running the underlying CI job instead.'
    });
  });
  
  const router = app.route('/api');

  router.use(bodyParser.json());

  const rawClientConfig = process.env.CLIENTS || '';
  // @ts-ignore
  const clients = new Map(rawClientConfig.split(';').map(c => c.split(':')));
  const verifyClient = (req, res, next) => {
    const clientKey = req.get('X-Client-Key');
    if (!clientKey) {
      res.status(401).json({
        message: 'No X-Client-Key header provided'
      });
      return;
    }

    if (!clients.has(clientKey)) {
      res.status(403).json({
        message: 'Invalid client key'
      });
      return;
    }

    const signature = req.get('X-Request-Signature');
    if (!signature) {
      res.status(401).json({
        message: 'No X-Request-Signature header provided'
      });
      return;
    }

    const bodyLength = req.get('Content-Length') || 0;
    const signingData = req.path + bodyLength + clients.get(clientKey);
    const expectedSignature = crypto.createHash('sha256')
      .update(signingData)
      .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
      res.status(403).json({
        message: 'Invalid request signature'
      });
      return;
    }

    next();
  }

  // Soft-load installations map on all requests
  router.use((req, res, next) => {
    loadOrgInstallations().then(next, err => {
      res.status(500).json(err);
    });
  });

  router.post('/check/:check_name/:owner/:repo/:sha', verifyClient, async (req, res) => {
    // Create a check run
    const { check_name, owner, repo, sha } = req.params;
    const installation = orgInstalls.get(owner);

    if (!installation) {
      res.status(403).json({
        error: 'Org does not have Checkers installed'
      });
      return;
    }

    console.log(req.body);
    console.log('type', typeof req.body);

    const {
      details_url,
      external_id,
      status,
      started_at,
      conclusion,
      completed_at,
      output
    } = req.body || {};

    try {
      const github = await app.auth(installation);
      const createRes = await github.checks.create({
        owner,
        repo,
        name: check_name,
        head_sha: sha,
        details_url,
        external_id,
        status,
        started_at,
        conclusion,
        completed_at,
        output
      });

      res.status(createRes.status).json(createRes.data);
    } catch (err) {
      res.status(500).json(err);
    }
  });

  router.patch('/check/:owner/:repo/:check_run_id', verifyClient, async (req, res) => {
    // Update an existing check run
    const { owner, repo, check_run_id } = req.params;
    const installation = orgInstalls.get(owner);

    if (!installation) {
      res.status(403).json({
        error: 'Org does not have Checkers installed'
      });
      return;
    }

    const checkRunId = parseInt(check_run_id, 10);
    if (Number.isNaN(checkRunId)) {
      res.status(400).json({
        error: 'Invalid check run ID'
      });
    }

    const {
      details_url,
      external_id,
      status,
      started_at,
      conclusion,
      completed_at,
      output
    } = req.body;

    try {
      const github = await app.auth(installation);
      const updateRes = await github.checks.update({
        owner,
        repo,
        check_run_id: checkRunId,
        details_url,
        external_id,
        status,
        started_at,
        conclusion,
        completed_at,
        output
      });
      
      res.status(updateRes.status).json(updateRes.data);
    } catch (err) {
      res.status((err && err.status) || 500).json(err);
    }
  });
}
