import { Clipboard } from '@angular/cdk/clipboard';
import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { ToastService } from 'src/app/services/toast.service';

interface PlaintextData {
  token: string;
  iatId: string;
}

@Component({
  selector: 'cnsl-iat-plaintext-dialog',
  templateUrl: './iat-plaintext-dialog.component.html',
  styleUrls: ['./iat-plaintext-dialog.component.scss'],
  standalone: false,
})
export class IatPlaintextDialogComponent {
  public revealed = false;

  constructor(
    @Inject(MAT_DIALOG_DATA) public readonly data: PlaintextData,
    private readonly clipboard: Clipboard,
    private readonly toast: ToastService,
    private readonly ref: MatDialogRef<IatPlaintextDialogComponent>,
  ) {}

  public reveal(): void {
    this.revealed = true;
  }

  public copy(): void {
    this.clipboard.copy(this.data.token);
    this.toast.showInfo('DESCRIPTIONS.DCR.IAT.COPIED', true);
  }

  public close(): void {
    this.ref.close();
  }
}
