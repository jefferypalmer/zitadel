import { Component } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef } from '@angular/material/dialog';

export interface IatIssueDialogResult {
  projectId: string;
  lifetimeSeconds: number;
  maxUses: number;
  allowedGrantTypes: string[];
  allowedRedirectUriPatterns: string[];
  description: string;
}

const HOUR_SECONDS = 3600;

@Component({
  selector: 'cnsl-iat-issue-dialog',
  templateUrl: './iat-issue-dialog.component.html',
  styleUrls: ['./iat-issue-dialog.component.scss'],
  standalone: false,
})
export class IatIssueDialogComponent {
  public readonly form = new FormGroup({
    projectId: new FormControl<string>('', { nonNullable: true, validators: [Validators.required] }),
    lifetimeHours: new FormControl<number>(24, { nonNullable: true, validators: [Validators.min(0)] }),
    maxUses: new FormControl<number>(1, { nonNullable: true, validators: [Validators.min(0)] }),
    allowedGrantTypes: new FormControl<string[]>([], { nonNullable: true }),
    allowedRedirectUriPatterns: new FormControl<string>('', { nonNullable: true }),
    description: new FormControl<string>('', { nonNullable: true }),
  });

  public readonly grantTypeOptions: ReadonlyArray<{ value: string; label: string }> = [
    { value: 'authorization_code', label: 'authorization_code' },
    { value: 'refresh_token', label: 'refresh_token' },
    { value: 'client_credentials', label: 'client_credentials' },
    { value: 'urn:ietf:params:oauth:grant-type:jwt-bearer', label: 'jwt-bearer' },
  ];

  constructor(private readonly ref: MatDialogRef<IatIssueDialogComponent, IatIssueDialogResult>) {}

  public cancel(): void {
    this.ref.close();
  }

  public submit(): void {
    if (this.form.invalid) {
      return;
    }
    const v = this.form.getRawValue();
    const patterns = v.allowedRedirectUriPatterns
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    this.ref.close({
      projectId: v.projectId.trim(),
      lifetimeSeconds: Math.max(0, v.lifetimeHours) * HOUR_SECONDS,
      maxUses: Math.max(0, v.maxUses),
      allowedGrantTypes: v.allowedGrantTypes,
      allowedRedirectUriPatterns: patterns,
      description: v.description,
    });
  }
}
