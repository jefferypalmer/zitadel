// dcr-helpers.ts — teardown helpers for the DCR Cypress specs.
//
// cavekit-console-ui-docs-and-observability.md R10 (T-020). Each spec's
// `afterEach()` calls these so re-running a spec twice in immediate
// sequence shows zero state accumulation. Both helpers are idempotent
// — tolerates already-revoked / already-deleted because parallel
// reruns commonly race a previous teardown. Teardown failures are
// logged via `cy.log` but do NOT fail the test (preserve the
// diagnostic signal from the actual assertions).

import { requestHeaders } from './api/apiauth';
import { API } from './api/types';

export function teardownIATs(api: API, projectId: string): void {
  if (!projectId) {
    cy.log('teardownIATs: missing projectId — skipping');
    return;
  }
  cy.request({
    method: 'POST',
    url: `${api.adminBaseURL}/initial_access_tokens/_search`,
    headers: requestHeaders(api),
    body: { query: { limit: 200, asc: false } },
    failOnStatusCode: false,
  }).then((listResp) => {
    if (listResp.status >= 400) {
      cy.log(`teardownIATs: list failed status=${listResp.status} — skipping (preserving test signal)`);
      return;
    }
    const rows: Array<{ id?: string; iatId?: string; projectId?: string }> = listResp.body?.result ?? [];
    rows
      .filter(r => (r.projectId ?? '') === projectId)
      .forEach(r => {
        const id = r.id ?? r.iatId;
        if (!id) return;
        cy.request({
          method: 'DELETE',
          url: `${api.adminBaseURL}/initial_access_tokens/${encodeURIComponent(id)}`,
          headers: requestHeaders(api),
          failOnStatusCode: false,
          body: { project_id: projectId },
        }).then(rev => {
          if (rev.status >= 400 && rev.status !== 404) {
            cy.log(`teardownIATs: revoke ${id} status=${rev.status} (tolerating; idempotent)`);
          }
        });
      });
  });
}

export function teardownDCRClients(api: API, projectId: string): void {
  if (!projectId) {
    cy.log('teardownDCRClients: missing projectId — skipping');
    return;
  }
  cy.request({
    method: 'POST',
    url: `${api.mgmtBaseURL}/projects/${encodeURIComponent(projectId)}/apps/_search`,
    headers: requestHeaders(api),
    body: { query: { limit: 200, asc: false } },
    failOnStatusCode: false,
  }).then((listResp) => {
    if (listResp.status >= 400) {
      cy.log(`teardownDCRClients: list failed status=${listResp.status} — skipping`);
      return;
    }
    const apps: Array<{ id: string; oidcConfig?: { dynamicallyRegistered?: boolean } }> = listResp.body?.result ?? [];
    apps
      .filter(app => app.oidcConfig?.dynamicallyRegistered === true)
      .forEach(app => {
        cy.request({
          method: 'DELETE',
          url: `${api.mgmtBaseURL}/projects/${encodeURIComponent(projectId)}/apps/${encodeURIComponent(app.id)}`,
          headers: requestHeaders(api),
          failOnStatusCode: false,
        }).then(del => {
          if (del.status >= 400 && del.status !== 404) {
            cy.log(`teardownDCRClients: delete ${app.id} status=${del.status} (tolerating; idempotent)`);
          }
        });
      });
  });
}
