import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { TranslateModule } from '@ngx-translate/core';
import { of } from 'rxjs';
import { MatDialog } from '@angular/material/dialog';

import { IatAdminComponent } from './iat-admin.component';
import { AdminService } from 'src/app/services/admin.service';
import { ToastService } from 'src/app/services/toast.service';

// cavekit-console-ui-docs-and-observability.md R9 (T-018) — presence test
// for [attr.aria-label] on the per-row revoke button. The translate
// pipe with TranslateModule.forRoot() in test mode renders the key
// verbatim when no translations are provided, which is sufficient to
// assert the *binding* is present (R9 separates locale population,
// owned by T-014, from binding hygiene, owned by T-018).

describe('IatAdminComponent', () => {
  let fixture: ComponentFixture<IatAdminComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot()],
      declarations: [IatAdminComponent],
      providers: [
        {
          provide: AdminService,
          useValue: {
            listInitialAccessTokens: () => Promise.resolve({ resultList: [], details: { totalResult: 0 } }),
          },
        },
        { provide: ToastService, useValue: { showError: () => {}, showInfo: () => {} } },
        { provide: MatDialog, useValue: { open: () => ({ afterClosed: () => of(undefined) }) } },
      ],
      schemas: [NO_ERRORS_SCHEMA],
    }).compileComponents();
    fixture = TestBed.createComponent(IatAdminComponent);
  });

  it('should create', () => {
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('per-row revoke button binds [attr.aria-label] to DESCRIPTIONS.DCR.IAT.REVOKE_BUTTON', () => {
    fixture.componentInstance.tokens$.next([
      { id: 'iat-1', projectId: 'p-1', revoked: false, maxUses: 0, usesConsumed: 0 } as never,
    ]);
    fixture.detectChanges();
    const revokeButton: HTMLElement | null =
      fixture.nativeElement.querySelector('[data-e2e="iat-revoke-button"]');
    expect(revokeButton).toBeTruthy();
    const aria = revokeButton?.getAttribute('aria-label') ?? '';
    expect(aria.length).toBeGreaterThan(0);
    expect(aria).toContain('DCR.IAT.REVOKE_BUTTON');
  });

  // cavekit-console-ui-docs-and-observability.md R9.2 (T-031). The
  // status-text-accompanies-color rule says the translated label MUST
  // be visible to sighted users — no `text-indent: -9999px`,
  // `font-size: 0`, or `display: none` masking the colored span.
  // Visual smoke verifies the SCSS but the kit explicitly requires a
  // getComputedStyle assertion in a unit test as well.
  it('status badge for a revoked row is visible (no text-indent/font-size:0/display:none)', () => {
    fixture.componentInstance.tokens$.next([
      { id: 'iat-1', projectId: 'p-1', revoked: true, maxUses: 0, usesConsumed: 0 } as never,
    ]);
    fixture.detectChanges();
    // Mat-table rows render the status column inside a span with class
    // 'iat-admin-status iat-admin-status--revoked'. We query directly.
    const badge: HTMLElement | null = fixture.nativeElement.querySelector('.iat-admin-status');
    expect(badge).toBeTruthy();
    const cs = window.getComputedStyle(badge as HTMLElement);
    // text-indent should not be a large negative (the off-screen trick).
    const ti = parseFloat(cs.textIndent || '0');
    expect(ti).toBeGreaterThanOrEqual(-1);
    // font-size must be non-zero.
    const fs = parseFloat(cs.fontSize || '0');
    expect(fs).toBeGreaterThan(0);
    // display must not be 'none'.
    expect(cs.display).not.toBe('none');
    // Translated label text must be present in the badge.
    expect((badge?.textContent ?? '').trim().length).toBeGreaterThan(0);
  });
});
