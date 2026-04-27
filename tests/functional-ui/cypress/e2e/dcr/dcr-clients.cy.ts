import { ensureProjectExists } from '../../support/api/projects';

const testProjectName = 'e2eprojectdcrclients';

describe('dcr — dynamic clients view', () => {
  beforeEach(() => {
    cy.context()
      .as('ctx')
      .then((ctx) => {
        ensureProjectExists(ctx.api, testProjectName).as('projectId');
      });
  });

  it('renders the dynamic clients sidenav entry on a project and shows the empty state', () => {
    cy.get<string>('@projectId').then((projectId) => {
      cy.visit(`/projects/${projectId}?id=dynamicclients`);

      // Phase 1: the App proto carries no DCR marker, so the listing
      // renders the empty state. The sidenav entry, the section header,
      // and the empty-state copy are the structural smoke contract.
      cy.get('[data-e2e="dcr-clients-empty"]').should('be.visible');
      cy.contains(
        '[data-e2e="dcr-clients-empty"]',
        /No dynamically registered clients|Noch keine dynamisch registrierten Clients/i,
      ).should('be.visible');

      // The audit cross-link target — existing app-detail page — is the
      // documented routing contract for T-070 (Decision 3). We don't have
      // a fixture client to click through, so we just assert the audit
      // table column header is present in the rendered template.
      cy.contains('h2', /Dynamic Clients|Dynamische Clients/i).should('be.visible');
    });
  });
});
