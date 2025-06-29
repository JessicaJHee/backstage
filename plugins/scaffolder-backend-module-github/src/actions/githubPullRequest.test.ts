/*
 * Copyright 2021 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Config, ConfigReader } from '@backstage/config';
import {
  GithubCredentialsProvider,
  ScmIntegrations,
} from '@backstage/integration';
import {
  ActionContext,
  TemplateAction,
} from '@backstage/plugin-scaffolder-node';
import fs from 'fs-extra';
import path from 'node:path';
import { createPublishGithubPullRequestAction } from './githubPullRequest';
import { createMockDirectory } from '@backstage/backend-test-utils';
import { createMockActionContext } from '@backstage/plugin-scaffolder-node-test-utils';
import { DELETE_FILE } from 'octokit-plugin-create-pull-request';

type GithubPullRequestActionInput = ReturnType<
  typeof createPublishGithubPullRequestAction
> extends TemplateAction<infer U, any, any>
  ? U
  : never;

describe('createPublishGithubPullRequestAction', () => {
  let instance: TemplateAction<GithubPullRequestActionInput, any, any>;
  let fakeClient: {
    createPullRequest: jest.Mock;
    rest: {
      pulls: { requestReviewers: jest.Mock };
      issues: { addAssignees: jest.Mock };
    };
  };
  let config: Config;
  let integrations: ScmIntegrations;

  const mockDir = createMockDirectory();
  const workspacePath = mockDir.resolve('workspace');

  beforeEach(() => {
    config = new ConfigReader({});
    integrations = ScmIntegrations.fromConfig(config);
    fakeClient = {
      createPullRequest: jest.fn(async (_: any) => {
        return {
          url: 'https://api.github.com/myorg/myrepo/pull/123',
          headers: {},
          status: 201,
          data: {
            html_url: 'https://github.com/myorg/myrepo/pull/123',
            number: 123,
            base: {
              ref: 'main',
            },
          },
        };
      }),
      rest: {
        pulls: {
          requestReviewers: jest.fn(async (_: any) => ({ data: {} })),
        },
        issues: {
          addAssignees: jest.fn(async (_: any) => ({ data: {} })),
        },
      },
    };
    const clientFactory = jest.fn(async () => fakeClient as any);
    const githubCredentialsProvider: GithubCredentialsProvider = {
      getCredentials: jest.fn(),
    };

    instance = createPublishGithubPullRequestAction({
      integrations,
      githubCredentialsProvider,
      clientFactory,
      config,
    });
  });

  afterEach(() => {
    mockDir.clear();
    jest.resetAllMocks();
  });

  describe('with targetBranchName', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      fakeClient = {
        createPullRequest: jest.fn(async (_: any) => {
          return {
            url: 'https://api.github.com/myorg/myrepo/pull/123',
            headers: {},
            status: 201,
            data: {
              html_url: 'https://github.com/myorg/myrepo/pull/123',
              number: 123,
              base: {
                ref: 'test',
              },
            },
          };
        }),
        rest: {
          pulls: {
            requestReviewers: jest.fn(async (_: any) => ({ data: {} })),
          },
          issues: {
            addAssignees: jest.fn(async (_: any) => ({ data: {} })),
          },
        },
      };

      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        targetBranchName: 'test',
        description: 'This PR is really good',
        draft: true,
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        base: 'test',
        body: 'This PR is really good',
        draft: true,
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });

    it('creates outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith('targetBranchName', 'test');
      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });
  });

  describe('with no sourcePath', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        draft: true,
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        draft: true,
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });

    it('creates outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith('targetBranchName', 'main');
      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });

    it('sets correct outputs during dry run', async () => {
      ctx.isDryRun = true;
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith('targetBranchName', 'new-app');
      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'github.com?owner=myorg&repo=myrepo',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 43);
    });
  });

  describe('with sourcePath', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        sourcePath: 'source',
      };

      mockDir.setContent({
        [workspacePath]: {
          source: { 'foo.txt': 'Hello there!' },
          irrelevant: { 'bar.txt': 'Nothing to see here' },
        },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request with only relevant files', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'foo.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });

    it('should not allow to use files outside of the workspace', async () => {
      input.sourcePath = '../../test';

      await expect(instance.handler(ctx)).rejects.toThrow(
        'Relative path is not allowed to refer to a directory outside its parent',
      );
    });
  });

  describe('with filesToDelete', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        filesToDelete: ['changed-file-to-delete.txt', 'delete-me-too.md'],
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({
        [workspacePath]: {
          'catpants.md': 'cat + pants',
          'changed-file-to-delete.txt': 'file is changed and deleted',
          'foobar.txt': 'Hello there!',
        },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('should delete named files', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: input.title,
        head: input.branchName,
        body: input.description,
        changes: [
          {
            commit: input.title,
            files: {
              'catpants.md': {
                content: Buffer.from('cat + pants').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
              'foobar.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
              'changed-file-to-delete.txt': DELETE_FILE,
              'delete-me-too.md': DELETE_FILE,
            },
          },
        ],
      });
    });

    describe('with targetPath', () => {
      const targetPath = `target-path-${Date.now()}`;

      beforeEach(() => {
        Object.assign(input, {
          filesToDelete: [
            path.posix.join('nested', 'catpants.md'),
            path.posix.join('nested', 'delete-me.too'),
          ],
          targetPath,
        });

        mockDir.setContent({
          [workspacePath]: {
            'catpants.md': 'cat + pants',
            'foobar.txt': 'Hello there!',
            [path.posix.join('nested', 'catpants.md')]: 'delete me',
            [path.posix.join('nested', 'delete-me.too')]: 'delete me too',
          },
        });
      });

      it('should delete named files', async () => {
        await instance.handler(ctx);

        expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
          owner: 'myorg',
          repo: 'myrepo',
          title: input.title,
          head: input.branchName,
          body: input.description,
          changes: [
            {
              commit: input.title,
              files: {
                [path.posix.join(targetPath, 'catpants.md')]: {
                  content: Buffer.from('cat + pants').toString('base64'),
                  encoding: 'base64',
                  mode: '100644',
                },
                [path.posix.join(targetPath, 'foobar.txt')]: {
                  content: Buffer.from('Hello there!').toString('base64'),
                  encoding: 'base64',
                  mode: '100644',
                },
                [path.posix.join(targetPath, 'nested', 'catpants.md')]:
                  DELETE_FILE,
                [path.posix.join(targetPath, 'nested', 'delete-me.too')]:
                  DELETE_FILE,
              },
            },
          ],
        });
      });
    });
  });

  describe('with repoUrl', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });
    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });

    it('creates outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });
  });

  describe('with reviewers and teamReviewers', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        reviewers: ['foobar'],
        teamReviewers: ['team-foo', 'team-foo', 'team-bar'],
      };

      mockDir.setContent({ [workspacePath]: {} });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request and requests a review from the given reviewers', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalled();
      expect(fakeClient.rest.pulls.requestReviewers).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        pull_number: 123,
        reviewers: ['foobar'],
        team_reviewers: ['team-foo', 'team-bar'],
      });
    });

    it('creates outputs for the pull request url and number even if requesting reviewers fails', async () => {
      fakeClient.rest.pulls.requestReviewers.mockImplementation(() => {
        throw new Error('a random error');
      });

      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });
  });

  describe('with no reviewers and teamReviewers', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({ [workspacePath]: {} });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('does not call the API endpoint for requesting reviewers', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalled();
      expect(fakeClient.rest.pulls.requestReviewers).not.toHaveBeenCalled();
    });
  });

  describe('with assignees', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        assignees: ['user1', 'user2'],
      };

      mockDir.setContent({ [workspacePath]: {} });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request and adds the assignees', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalled();
      expect(fakeClient.rest.issues.addAssignees).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        issue_number: 123,
        assignees: ['user1', 'user2'],
      });
    });
    it('creates outputs for the pull request url and number even if adding assignees fails', async () => {
      fakeClient.rest.issues.addAssignees.mockImplementation(() => {
        throw new Error('a random error');
      });

      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });
  });

  describe('with broken symlink', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({
        [workspacePath]: {
          Makefile: c => c.symlink('../../nothing/yet'),
        },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });
    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              Makefile: {
                content: Buffer.from('../../nothing/yet').toString('utf-8'),
                encoding: 'utf-8',
                mode: '120000',
              },
            },
          },
        ],
      });
    });
  });

  describe('with executable file mode 755', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({
        [workspacePath]: {
          'hello.sh': c =>
            fs.writeFileSync(c.path, 'echo Hello there!', {
              encoding: 'utf8',
              mode: 0o100755,
            }),
        },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });
    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'hello.sh': {
                content: Buffer.from('echo Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100755',
              },
            },
          },
        ],
      });
    });

    it('creates outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });
  });

  describe('with executable file mode 775', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({
        [workspacePath]: {
          'hello.sh': c =>
            fs.writeFileSync(c.path, 'echo Hello there!', {
              encoding: 'utf8',
              mode: 0o100775,
            }),
        },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });
    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'hello.sh': {
                content: Buffer.from('echo Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100755',
              },
            },
          },
        ],
      });
    });

    it('creates outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });
  });

  describe('with commit message', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        commitMessage: 'Create my new app, but in the commit message',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app, but in the commit message',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });
  });

  describe('with force fork', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        forceFork: true,
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
        forceFork: true,
      });
    });
  });

  describe('with author name and email', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        gitAuthorEmail: 'foo@bar.example',
        gitAuthorName: 'Foo Bar',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
            author: {
              email: 'foo@bar.example',
              name: 'Foo Bar',
            },
          },
        ],
      });
    });
  });

  describe('with author name', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        gitAuthorName: 'Foo Bar',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
            author: {
              email: 'scaffolder@backstage.io',
              name: 'Foo Bar',
            },
          },
        ],
      });
    });
  });

  describe('with author email', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        gitAuthorEmail: 'foo@bar.example',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
            author: {
              email: 'foo@bar.example',
              name: 'Scaffolder',
            },
          },
        ],
      });
    });
  });

  describe('with author from config file', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request with default config attributes', async () => {
      config = new ConfigReader({
        scaffolder: {
          defaultAuthor: {
            name: 'Config',
            email: 'config@file.example',
          },
        },
      });

      const clientFactory = jest.fn(async () => fakeClient as any);
      const githubCredentialsProvider: GithubCredentialsProvider = {
        getCredentials: jest.fn(),
      };

      const instanceWithConfig = createPublishGithubPullRequestAction({
        integrations,
        githubCredentialsProvider,
        clientFactory,
        config,
      });

      await instanceWithConfig.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
            author: {
              email: 'config@file.example',
              name: 'Config',
            },
          },
        ],
      });
    });
  });

  describe('with author attributes and config file', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        gitAuthorEmail: 'foo@bar.example',
        gitAuthorName: 'Foo Bar',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request with using author name and email from input', async () => {
      config = new ConfigReader({
        scaffolder: {
          defaultAuthor: {
            name: 'Config',
            email: 'config@file.example',
          },
        },
      });

      const clientFactory = jest.fn(async () => fakeClient as any);
      const githubCredentialsProvider: GithubCredentialsProvider = {
        getCredentials: jest.fn(),
      };

      const instanceWithConfig = createPublishGithubPullRequestAction({
        integrations,
        githubCredentialsProvider,
        clientFactory,
        config,
      });

      await instanceWithConfig.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
            author: {
              email: 'foo@bar.example',
              name: 'Foo Bar',
            },
          },
        ],
      });
    });
  });

  describe('with author fallback and no config', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        gitAuthorName: 'Foo Bar',
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });

    it('creates a pull request with using author name and email fallback when have no config', async () => {
      const clientFactory = jest.fn(async () => fakeClient as any);
      const githubCredentialsProvider: GithubCredentialsProvider = {
        getCredentials: jest.fn(),
      };

      const instanceWithConfig = createPublishGithubPullRequestAction({
        integrations,
        githubCredentialsProvider,
        clientFactory,
      });

      await instanceWithConfig.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
            author: {
              email: 'scaffolder@backstage.io',
              name: 'Foo Bar',
            },
          },
        ],
      });
    });
    it('discards author name and email if forceEmptyGitAuthor is set', async () => {
      input.forceEmptyGitAuthor = true;
      const clientFactory = jest.fn(async () => fakeClient as any);
      const githubCredentialsProvider: GithubCredentialsProvider = {
        getCredentials: jest.fn(),
      };

      const instanceWithConfig = createPublishGithubPullRequestAction({
        integrations,
        githubCredentialsProvider,
        clientFactory,
      });

      await instanceWithConfig.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });
  });

  describe('with createWhenEmpty equals true', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        createWhenEmpty: true,
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });
    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        createWhenEmpty: true,
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });

    it('creates outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).toHaveBeenCalledWith(
        'remoteUrl',
        'https://github.com/myorg/myrepo/pull/123',
      );
      expect(ctx.output).toHaveBeenCalledWith('pullRequestNumber', 123);
    });

    it('throws when creating a pull request fails', async () => {
      fakeClient.createPullRequest.mockResolvedValueOnce(null);

      await expect(instance.handler(ctx)).rejects.toThrow(
        'null response from Github',
      );
    });
  });

  describe('with createWhenEmpty equals false', () => {
    let input: GithubPullRequestActionInput;
    let ctx: ActionContext<GithubPullRequestActionInput, any, any>;

    beforeEach(() => {
      fakeClient.createPullRequest.mockResolvedValueOnce(null);
      input = {
        repoUrl: 'github.com?owner=myorg&repo=myrepo',
        title: 'Create my new app',
        branchName: 'new-app',
        description: 'This PR is really good',
        createWhenEmpty: false,
      };

      mockDir.setContent({
        [workspacePath]: { 'file.txt': 'Hello there!' },
      });

      ctx = createMockActionContext({ input, workspacePath });
    });
    it('creates a pull request', async () => {
      await instance.handler(ctx);

      expect(fakeClient.createPullRequest).toHaveBeenCalledWith({
        owner: 'myorg',
        repo: 'myrepo',
        title: 'Create my new app',
        head: 'new-app',
        body: 'This PR is really good',
        createWhenEmpty: false,
        changes: [
          {
            commit: 'Create my new app',
            files: {
              'file.txt': {
                content: Buffer.from('Hello there!').toString('base64'),
                encoding: 'base64',
                mode: '100644',
              },
            },
          },
        ],
      });
    });

    it('does not create outputs for the pull request url and number', async () => {
      await instance.handler(ctx);

      expect(ctx.output).not.toHaveBeenCalled();
    });
  });
});
