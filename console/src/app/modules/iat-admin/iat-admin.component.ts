import { Component, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { Duration } from 'google-protobuf/google/protobuf/duration_pb';
import { BehaviorSubject, from, Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { CreateInitialAccessTokenRequest, InitialAccessTokenView } from 'src/app/proto/generated/zitadel/admin_pb';
import { ListQuery } from 'src/app/proto/generated/zitadel/object_pb';
import { PageEvent, PaginatorComponent } from 'src/app/modules/paginator/paginator.component';
import { AdminService } from 'src/app/services/admin.service';
import { ToastService } from 'src/app/services/toast.service';

import { IatIssueDialogComponent, IatIssueDialogResult } from './iat-issue-dialog/iat-issue-dialog.component';
import { IatPlaintextDialogComponent } from './iat-plaintext-dialog/iat-plaintext-dialog.component';
import { IatRevokeDialogComponent } from './iat-revoke-dialog/iat-revoke-dialog.component';

const INITIAL_PAGE_SIZE = 100;

@Component({
  selector: 'cnsl-iat-admin',
  templateUrl: './iat-admin.component.html',
  styleUrls: ['./iat-admin.component.scss'],
  standalone: false,
})
export class IatAdminComponent implements OnInit, OnDestroy {
  public readonly displayedColumns = ['id', 'projectId', 'expiresAt', 'maxUses', 'usesConsumed', 'revoked', 'actions'];
  public readonly tokens$ = new BehaviorSubject<InitialAccessTokenView.AsObject[]>([]);
  public readonly loading$ = new BehaviorSubject<boolean>(false);
  public readonly totalResult$ = new BehaviorSubject<number>(0);
  public readonly pageSize = INITIAL_PAGE_SIZE;
  @ViewChild(PaginatorComponent) public paginator?: PaginatorComponent;

  // cavekit-console-ui-docs-and-observability.md R9 (T-016) — completes
  // in ngOnDestroy so every subscription teed off this Subject via
  // takeUntil(destroy$) is torn down on navigate-away.
  private readonly destroy$ = new Subject<void>();

  // T-017 trackBy: row identity is the IAT id; without this the table
  // re-renders every row on each refresh because Angular default uses
  // object identity, and the listInitialAccessTokens response builds a
  // fresh array each call.
  // T-033 (F-011): defensive nullish-coalesce in case a malformed row
  // arrives without an id — Angular's trackBy MUST not throw.
  public readonly trackById = (_: number, row?: { id?: string }) => row?.id ?? '';

  constructor(
    private readonly admin: AdminService,
    private readonly dialog: MatDialog,
    private readonly toast: ToastService,
  ) {}

  public ngOnInit(): void {
    this.loadPage(0, INITIAL_PAGE_SIZE);
  }

  public ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  public refresh(): void {
    this.loadPage(this.paginator?.pageIndex ?? 0, this.paginator?.pageSize ?? INITIAL_PAGE_SIZE);
  }

  public loadPage(pageIndex: number, pageSize: number): void {
    if (this.loading$.value) {
      // F-007 guard: refuse a second concurrent fetch (also prevents a
      // double-click from racing the toast for the previous request).
      return;
    }
    const query = new ListQuery();
    query.setLimit(pageSize);
    query.setOffset(pageIndex * pageSize);
    this.loading$.next(true);
    // T-032 (F-010): route the Promise through takeUntil(destroy$) so a
    // navigate-away mid-fetch stops the .next() side-effects on
    // tokens$/loading$/totalResult$. Without this the BehaviorSubjects
    // continue accepting values after the component is disposed.
    from(this.admin.listInitialAccessTokens(null, query))
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (resp) => {
          this.tokens$.next(resp.resultList ?? []);
          this.totalResult$.next(resp.details?.totalResult ? Number(resp.details.totalResult) : 0);
          this.loading$.next(false);
        },
        error: (err) => {
          this.toast.showError(err);
          this.loading$.next(false);
        },
      });
  }

  public onPaginatorChange(event: PageEvent): void {
    this.loadPage(event.pageIndex, event.pageSize);
  }

  public openIssueDialog(): void {
    if (this.loading$.value) {
      return;
    }
    const ref = this.dialog.open<IatIssueDialogComponent, void, IatIssueDialogResult>(IatIssueDialogComponent, {
      width: '520px',
    });
    ref.afterClosed().pipe(takeUntil(this.destroy$)).subscribe((result) => {
      if (!result) {
        return;
      }
      const req = new CreateInitialAccessTokenRequest();
      req.setProjectId(result.projectId);
      if (result.lifetimeSeconds > 0) {
        const dur = new Duration();
        dur.setSeconds(result.lifetimeSeconds);
        req.setLifetime(dur);
      }
      req.setMaxUses(result.maxUses);
      req.setAllowedGrantTypesList(result.allowedGrantTypes);
      req.setAllowedRedirectUriPatternsList(result.allowedRedirectUriPatterns);
      req.setDescription(result.description);

      this.admin
        .createInitialAccessToken(req)
        .then((resp) => {
          // R2 AC3 (kit-amended 2026-04-27): the plaintext modal is the
          // ONLY surface for the token. We pass the plaintext into the
          // dialog's MAT_DIALOG_DATA and immediately drop our local
          // reference. The dialog itself zeroes data.token on close
          // (T-094) and never returns it through afterClosed.
          const plaintext = resp.token;
          const iatId = resp.iatId;
          // Clear the local copy held by the response Promise scope —
          // the only retained reference now lives on the dialog's data
          // object until close().
          (resp as { token?: string }).token = '';
          this.dialog.open(IatPlaintextDialogComponent, {
            width: '560px',
            disableClose: true,
            data: { token: plaintext, iatId },
          });
          this.refresh();
        })
        .catch((err) => this.toast.showError(err));
    });
  }

  public revoke(token: InitialAccessTokenView.AsObject): void {
    // T-093 guard: the IAT view's projectId is required by RevokeInitialAccessTokenRequest
    // server-side validation; refuse to dispatch if a malformed row arrives without one.
    if (!token.projectId) {
      this.toast.showInfo('DESCRIPTIONS.DCR.IAT.REVOKE_PROJECT_REQUIRED', true);
      return;
    }
    const ref = this.dialog.open<IatRevokeDialogComponent, void, boolean>(IatRevokeDialogComponent, {
      width: '400px',
    });
    ref.afterClosed().pipe(takeUntil(this.destroy$)).subscribe((confirmed) => {
      if (!confirmed) {
        return;
      }
      this.admin
        .revokeInitialAccessToken(token.id, token.projectId)
        .then(() => {
          this.toast.showInfo('DESCRIPTIONS.DCR.IAT.REVOKED', true);
          this.refresh();
        })
        .catch((err) => this.toast.showError(err));
    });
  }
}
