import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { Duration } from 'google-protobuf/google/protobuf/duration_pb';
import { BehaviorSubject } from 'rxjs';
import { CreateInitialAccessTokenRequest, InitialAccessTokenView } from 'src/app/proto/generated/zitadel/admin_pb';
import { AdminService } from 'src/app/services/admin.service';
import { ToastService } from 'src/app/services/toast.service';

import { IatIssueDialogComponent, IatIssueDialogResult } from './iat-issue-dialog/iat-issue-dialog.component';
import { IatPlaintextDialogComponent } from './iat-plaintext-dialog/iat-plaintext-dialog.component';
import { IatRevokeDialogComponent } from './iat-revoke-dialog/iat-revoke-dialog.component';

@Component({
  selector: 'cnsl-iat-admin',
  templateUrl: './iat-admin.component.html',
  styleUrls: ['./iat-admin.component.scss'],
  standalone: false,
})
export class IatAdminComponent implements OnInit {
  public readonly displayedColumns = ['id', 'projectId', 'expiresAt', 'maxUses', 'usesConsumed', 'revoked', 'actions'];
  public readonly tokens$ = new BehaviorSubject<InitialAccessTokenView.AsObject[]>([]);
  public readonly loading$ = new BehaviorSubject<boolean>(false);

  constructor(
    private readonly admin: AdminService,
    private readonly dialog: MatDialog,
    private readonly toast: ToastService,
  ) {}

  public ngOnInit(): void {
    this.refresh();
  }

  public refresh(): void {
    this.loading$.next(true);
    this.admin
      .listInitialAccessTokens(null)
      .then((resp) => this.tokens$.next(resp.resultList ?? []))
      .catch((err) => this.toast.showError(err))
      .finally(() => this.loading$.next(false));
  }

  public openIssueDialog(): void {
    const ref = this.dialog.open<IatIssueDialogComponent, void, IatIssueDialogResult>(IatIssueDialogComponent, {
      width: '520px',
    });
    ref.afterClosed().subscribe((result) => {
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
          // R2 AC3: show plaintext EXACTLY ONCE in a modal that doesn't
          // expose the token through any other UI surface. After this
          // dialog closes, the plaintext is unrecoverable from frontend
          // state (the response object is not retained anywhere).
          this.dialog.open(IatPlaintextDialogComponent, {
            width: '560px',
            disableClose: true,
            data: { token: resp.token, iatId: resp.iatId },
          });
          this.refresh();
        })
        .catch((err) => this.toast.showError(err));
    });
  }

  public revoke(token: InitialAccessTokenView.AsObject): void {
    const ref = this.dialog.open<IatRevokeDialogComponent, void, boolean>(IatRevokeDialogComponent, {
      width: '400px',
    });
    ref.afterClosed().subscribe((confirmed) => {
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
