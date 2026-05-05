import { requestHeaders } from '../../support/api/apiauth';
import { ensureProjectExists } from '../../support/api/projects';
import { teardownDCRClients, teardownIATs } from '../../support/dcr-helpers';
import { Context } from 'support/commands';

const testProjectName = 'e2eprojectdcrclients';

describe('dcr — dynamic clients view', () => {
  beforeEach(() => {
    cy.context()
      .as('ctx')
      .then((ctx) => {
        ensureProjectExists(ctx.api, testProjectName).as('projectId');
      });
  });

  // cavekit-console-ui-docs-and-observability.md R10 (T-020). Two-stage
  // cleanup: drop every DCR-registered app under the project, then
  // revoke every IAT under the project (the registration consumed an
  // IAT but the project may carry stale fixtures from a partial run).
  afterEach(() => {
    cy.get<Context>('@ctx').then((ctx) => {
      cy.get<string>('@projectId').then((projectId) => {
        teardownDCRClients(ctx.api, projectId);
        teardownIATs(ctx.api, projectId);
      });
    });
  });

  it('renders the dynamic clients sidenav entry on a project and shows the empty state', () => {
    cy.get<string>('@projectId').then((projectId) => {
      cy.visit(`/projects/${projectId}?id=dynamicclients`);
      cy.get('[data-e2e="dcr-clients-empty"]').should('be.visible');
      cy.contains(
        '[data-e2e="dcr-clients-empty"]',
        /No dynamically registered clients|Noch keine dynamisch registrierten Clients/i,
      ).should('be.visible');
      cy.contains('h2', /Dynamic Clients|Dynamische Clients/i).should('be.visible');
    });
  });

  it('lists a DCR-registered client and routes the audit link to app-detail', () => {
    cy.get<Context>('@ctx').then((ctx) => {
      cy.get<string>('@projectId').then((projectId) => {
        // Step 1: mint an Initial Access Token via admin gRPC scoped to this project.
        // The IAT authorizes the subsequent /oidc/v1/register call (RFC 7591).
        cy.request({
          method: 'POST',
          url: `${ctx.api.adminBaseURL}/initial_access_tokens`,
          headers: requestHeaders(ctx.api),
          body: {
            project_id: projectId,
            lifetime: '300s',
            max_uses: 1,
            description: 'e2e dcr-clients fixture',
          },
        }).then((iatResp) => {
          const iat = iatResp.body.token as string;
          expect(iat, 'IAT plaintext').to.match(/^zdiat_/);

          // Step 2: POST to /oidc/v1/register with the IAT to materialize a DCR client.
          // RFC 7591 §3.1 form: redirect_uris + token_endpoint_auth_method=none
          // gives us a public PKCE client without needing a secret.
          const backendUrl = Cypress.env('BACKEND_URL');
          cy.request({
            method: 'POST',
            url: `${backendUrl}/oidc/v1/register`,
            headers: { Authorization: `Bearer ${iat}`, 'Content-Type': 'application/json' },
            body: {
              client_name: 'e2e-dcr-fixture',
              redirect_uris: ['http://localhost:3000/cb'],
              token_endpoint_auth_method: 'none',
              grant_types: ['authorization_code', 'refresh_token'],
              response_types: ['code'],
              application_type: 'native',
            },
          }).then((regResp) => {
            const dcrClientId = regResp.body.client_id as string;
            expect(dcrClientId, 'DCR client_id').to.be.a('string').and.not.empty;

            // Step 3: visit the project's Dynamic Clients view.
            cy.visit(`/projects/${projectId}?id=dynamicclients`);

            // Step 4: assert the row appears with our DCR client id.
            cy.get('[data-e2e="dcr-clients-table"]', { timeout: 10_000 })
              .should('be.visible')
              .and('contain.text', dcrClientId);

            // Step 5: click the audit-link icon and assert navigation
            // to /projects/:projectId/apps/:appId. The DCR-registered
            // client appears as a standard Application (ADR-0001 D-3),
            // so the audit history is rendered by the existing
            // <cnsl-changes [changeType]="ChangeType.APP"> mount.
            cy.get('[data-e2e="dcr-clients-table"]').contains('tr', dcrClientId).find('a[mat-icon-button]').click();
            cy.url().should('match', new RegExp(`/projects/${projectId}/apps/`));
          });
        });
      });
    });
  });
});
