import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';

@Component({
  selector: 'cnsl-iat-revoke-dialog',
  templateUrl: './iat-revoke-dialog.component.html',
  standalone: false,
})
export class IatRevokeDialogComponent {
  constructor(private readonly ref: MatDialogRef<IatRevokeDialogComponent, boolean>) {}

  public cancel(): void {
    this.ref.close(false);
  }

  public confirm(): void {
    this.ref.close(true);
  }
}
