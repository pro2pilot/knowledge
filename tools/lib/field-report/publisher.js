'use strict';

const childProcess = require('child_process');

function safeError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function graphql(query, variables = {}, options = {}) {
  const args = ['api', 'graphql', '-f', `query=${query}`];
  for (const [key, value] of Object.entries(variables)) {
    if (value === undefined || value === null) continue;
    args.push('-f', `${key}=${value}`);
  }
  const result = childProcess.spawnSync('gh', args, {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 60 * 1000,
    maxBuffer: 8 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw safeError(
      options.mutation
        ? 'GitHub publication response was unavailable; the remote outcome must be reconciled.'
        : 'GitHub authentication or network request failed.',
      options.mutation ? 'publish_outcome_unknown' : 'publish_auth'
    );
  }
  try {
    const parsed = JSON.parse(result.stdout);
    if (parsed.errors?.length) throw new Error('GraphQL errors');
    return parsed.data;
  } catch {
    throw safeError(
      options.mutation
        ? 'GitHub returned an invalid publication response; the remote outcome must be reconciled.'
        : 'GitHub returned an invalid GraphQL response.',
      options.mutation ? 'publish_outcome_unknown' : 'publish_network'
    );
  }
}

function splitRepository(repository) {
  const [owner, name, extra] = String(repository || '').split('/');
  if (!owner || !name || extra) {
    throw safeError('Discussion repository must use owner/name format.', 'publish_target');
  }
  return { owner, name };
}

function authenticateGithub(payload) {
  const { owner, name } = splitRepository(payload.repository);
  const data = graphql(
    'query($owner:String!,$name:String!){viewer{login}repository(owner:$owner,name:$name){' +
    'id discussionCategories(first:100){nodes{id slug name}}}}',
    { owner, name }
  );
  const repository = data.repository;
  const wanted = String(payload.category_slug || '').toLowerCase();
  const category = repository?.discussionCategories?.nodes?.find((item) =>
    String(item.slug).toLowerCase() === wanted
  );
  if (!data.viewer?.login) {
    throw safeError('GitHub did not return the authenticated actor.', 'publish_auth');
  }
  if (!repository?.id || !category?.id) {
    throw safeError(
      `Discussion category not found: ${payload.category_slug}`,
      'publish_target'
    );
  }
  return {
    actor: data.viewer.login,
    repository: payload.repository,
    category_slug: String(category.slug),
    repository_id: repository.id,
    category_id: category.id
  };
}

function createGithubDiscussion(payload, authentication) {
  const data = graphql(
    'mutation($repositoryId:ID!,$categoryId:ID!,$title:String!,$body:String!){' +
    'createDiscussion(input:{repositoryId:$repositoryId,categoryId:$categoryId,' +
    'title:$title,body:$body}){discussion{id url}}}',
    {
      repositoryId: authentication.repository_id,
      categoryId: authentication.category_id,
      title: payload.title,
      body: payload.body
    },
    { mutation: true }
  );
  const discussion = data.createDiscussion?.discussion;
  if (!discussion?.id || !discussion?.url) {
    throw safeError(
      'GitHub did not return a Discussion identifier and URL.',
      'publish_network'
    );
  }
  return {
    discussion_id: discussion.id,
    url: discussion.url,
    actor: authentication.actor,
    repository: authentication.repository,
    category_slug: authentication.category_slug
  };
}

function lookupGithubDiscussion(payload, authentication, options = {}) {
  const { owner, name } = splitRepository(payload.repository);
  const marker = String(options.idempotencyMarker || payload.idempotency_marker || '');
  if (!marker) {
    throw safeError('Publication reconciliation requires an idempotency marker.', 'publish_reconcile');
  }
  const query =
    'query($owner:String!,$name:String!,$cursor:String){repository(owner:$owner,name:$name){' +
    'discussions(first:100,after:$cursor,orderBy:{field:CREATED_AT,direction:DESC}){' +
    'nodes{id url title body author{login} category{slug}}' +
    'pageInfo{hasNextPage endCursor}}}}';
  const matches = [];
  let cursor = null;
  let pages = 0;
  let exhausted = false;
  while (pages < 100) {
    pages += 1;
    const data = graphql(query, { owner, name, cursor });
    const discussions = data.repository?.discussions;
    if (!discussions || !Array.isArray(discussions.nodes)) {
      throw safeError('GitHub Discussion reconciliation response was incomplete.', 'publish_reconcile');
    }
    for (const discussion of discussions.nodes) {
      if (!String(discussion?.body || '').includes(marker)) continue;
      matches.push({
        discussion_id: discussion.id,
        url: discussion.url,
        actor: discussion.author?.login || null,
        repository: payload.repository,
        category_slug: discussion.category?.slug || null,
        title: discussion.title,
        body: discussion.body
      });
    }
    if (!discussions.pageInfo?.hasNextPage) {
      exhausted = true;
      break;
    }
    cursor = discussions.pageInfo?.endCursor;
    if (!cursor) {
      throw safeError('GitHub Discussion reconciliation cursor was missing.', 'publish_reconcile');
    }
  }
  if (!exhausted) {
    throw safeError('GitHub Discussion reconciliation was not exhaustive.', 'publish_reconcile');
  }
  if (matches.length > 1) {
    throw safeError('Multiple Discussions matched the publication idempotency key.', 'publish_reconcile_ambiguous');
  }
  return matches[0] || null;
}

const githubAdapter = Object.freeze({
  name: 'github-cli',
  testOnly: false,
  authenticate: authenticateGithub,
  lookup: lookupGithubDiscussion,
  publish: createGithubDiscussion
});

function adapterIsTestOnly(adapter) {
  return Boolean(adapter && adapter !== githubAdapter && adapter.testOnly === true);
}

function authenticate(payload, options = {}) {
  const adapter = options.adapter || githubAdapter;
  if (typeof adapter === 'function') {
    const result = adapter(payload, { ...options, action: 'preview', dryRun: true });
    if (!result?.actor) {
      throw safeError(
        'Injected publisher did not return an authenticated actor.',
        'publish_auth'
      );
    }
    return {
      actor: result.actor,
      repository: result.repository || payload.repository,
      category_slug: result.category_slug || payload.category_slug,
      injected: true
    };
  }
  if (typeof adapter.authenticate !== 'function') {
    throw safeError('Publisher adapter does not implement authenticate().', 'publish_adapter');
  }
  return adapter.authenticate(payload, options);
}

function publish(payload, authentication, options = {}) {
  const adapter = options.adapter || githubAdapter;
  if (typeof adapter === 'function') {
    return adapter(payload, {
      ...options,
      action: 'publish',
      authentication,
      dryRun: false
    });
  }
  if (typeof adapter.publish !== 'function') {
    throw safeError('Publisher adapter does not implement publish().', 'publish_adapter');
  }
  return adapter.publish(payload, authentication, options);
}

function lookup(payload, authentication, options = {}) {
  const adapter = options.adapter || githubAdapter;
  if (typeof adapter.lookup !== 'function') {
    throw safeError(
      'Publisher adapter cannot reconcile an uncertain remote outcome.',
      'publish_reconcile_unavailable'
    );
  }
  return adapter.lookup(payload, authentication, options);
}

module.exports = {
  adapterIsTestOnly,
  authenticate,
  githubAdapter,
  lookup,
  publish,
  __test: {
    authenticateGithub,
    createGithubDiscussion,
    graphql,
    lookupGithubDiscussion,
    splitRepository
  }
};
