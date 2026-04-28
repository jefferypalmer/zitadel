import { Clipboard } from '@angular/cdk/clipboard';
import { Component, Inject, OnDestroy } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { ToastService } from 'src/app/services/toast.service';

// PlaintextData is mutable on purpose — see close()/remask() which zero
// the token reference. Do NOT mark `token` readonly.
interface PlaintextData {
  token: string;
  iatId: string;
}

// Auto-mask after this many milliseconds (T-097 — bounded shoulder-surf
// window). Re-mask button (`remask()`) lets the user hide the token sooner.
const REVEAL_AUTO_MASK_MS = 60_000;

@Component({
  selector: 'cnsl-iat-plaintext-dialog',
  templateUrl: './iat-plaintext-dialog.component.html',
  styleUrls: ['./iat-plaintext-dialog.component.scss'],
  standalone: false,
})
export class IatPlaintextDialogComponent implements OnDestroy {
  public revealed = false;
  private autoMaskTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    @Inject(MAT_DIALOG_DATA) public readonly data: PlaintextData,
    private readonly clipboard: Clipboard,
    private readonly toast: ToastService,
    private readonly ref: MatDialogRef<IatPlaintextDialogComponent>,
  ) {}

  public reveal(): void {
    this.revealed = true;
    this.scheduleAutoMask();
  }

  public remask(): void {
    this.revealed = false;
    this.cancelAutoMask();
  }

  public copy(): void {
    this.clipboard.copy(this.data.token);
    this.toast.showInfo('DESCRIPTIONS.DCR.IAT.COPIED', true);
  }

  public close(): void {
    // T-094 (R2 AC3 amended): zero the in-memory token before closing.
    // The dialog instance lives on `MatDialogRef.componentInstance` until
    // GC; the component instance owns `data` but `data.token` was just
    // emptied, so a leaked reference reads "" instead of the secret.
    this.data.token = '';
    this.cancelAutoMask();
    // Pass nothing through afterClosed() — never the plaintext.
    this.ref.close();
  }

  public ngOnDestroy(): void {
    // Defense in depth: even if `close()` was bypassed (e.g., MatDialog
    // global close), zero the token on destruction.
    this.data.token = '';
    this.cancelAutoMask();
  }

  private scheduleAutoMask(): void {
    this.cancelAutoMask();
    this.autoMaskTimer = setTimeout(() => {
      this.revealed = false;
      this.autoMaskTimer = null;
    }, REVEAL_AUTO_MASK_MS);
  }

  private cancelAutoMask(): void {
    if (this.autoMaskTimer !== null) {
      clearTimeout(this.autoMaskTimer);
      this.autoMaskTimer = null;
    }
  }
}
