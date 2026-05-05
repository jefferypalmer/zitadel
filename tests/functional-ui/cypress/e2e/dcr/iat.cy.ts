import { ensureProjectExists } from '../../support/api/projects';
import { teardownIATs } from '../../support/dcr-helpers';
import { Context } from 'support/commands';

const testProjectName = 'e2eprojectdcriat';

describe('dcr — initial access tokens', () => {
  beforeEach(() => {
    cy.context()
      .as('ctx')
      .then((ctx) => {
        ensureProjectExists(ctx.api, testProjectName).as('projectId');
      });
  });

  // cavekit-console-ui-docs-and-observability.md R10 (T-020) — leave the
  // instance with zero IATs scoped to this project so a second run of
  // this spec sees a clean projection. Teardown failures are logged
  // but do NOT fail the test.
  afterEach(() => {
    cy.get<Context>('@ctx').then((ctx) => {
      cy.get<string>('@projectId').then((projectId) => {
        teardownIATs(ctx.api, projectId);
      });
    });
  });

  it('issues, lists, and revokes an initial access token', () => {
    cy.get<string>('@projectId').then((projectId) => {
      // Land on the instance settings IAT admin surface.
      cy.visit('/instance?id=initialaccesstokens');

      // Issue.
      cy.get('[data-e2e="iat-issue-button"]').should('be.visible').click();

      cy.get('[formcontrolname="projectId"]').focus().should('be.enabled').type(projectId);
      cy.get('[formcontrolname="lifetimeHours"]').focus().clear().type('24');
      cy.get('[formcontrolname="maxUses"]').focus().clear().type('1');
      cy.get('[formcontrolname="description"]').focus().type('e2e iat smoke');

      cy.get('[data-e2e="iat-issue-submit"]').should('be.enabled').click();

      // Plaintext modal renders. The kit (R2 AC3) requires the token shown
      // exactly once with a clipboard affordance and a "you cannot retrieve
      // this again" warning. We don't try to copy the token in CI (clipboard
      // permissions vary by runner) — just assert the warning + close.
      cy.contains('[mat-dialog-title], h2', /Token Issued|Token ausgestellt/i).should('be.visible');
      cy.contains('button', /I've Saved It|Ich habe ihn gespeichert/i)
        .should('be.visible')
        .click();

      // Listing now contains an active row for our project.
      cy.get('[data-e2e="iat-admin-table"]').should('contain.text', projectId);

      // Revoke first row.
      cy.get('[data-e2e="iat-revoke-button"]').first().should('be.visible').click();
      cy.get('[data-e2e="iat-revoke-confirm"]').should('be.visible').click();

      // Active revoke icon should disappear (or the row's status flips to revoked).
      // We assert at least one revoked-status badge appears for our project.
      cy.get('[data-e2e="iat-admin-table"]')
        .contains('tr', projectId)
        .invoke('text')
        .should('match', /Revoked|Widerrufen/i);
    });
  });
});
