import { ClipboardModule } from '@angular/cdk/clipboard';
import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { TranslateModule } from '@ngx-translate/core';
import { CardModule } from 'src/app/modules/card/card.module';
import { PaginatorModule } from 'src/app/modules/paginator/paginator.module';
import { LocalizedDatePipeModule } from 'src/app/pipes/localized-date-pipe/localized-date-pipe.module';
import { TimestampToDatePipeModule } from 'src/app/pipes/timestamp-to-date-pipe/timestamp-to-date-pipe.module';

import { IatAdminComponent } from './iat-admin.component';
import { IatIssueDialogComponent } from './iat-issue-dialog/iat-issue-dialog.component';
import { IatPlaintextDialogComponent } from './iat-plaintext-dialog/iat-plaintext-dialog.component';
import { IatRevokeDialogComponent } from './iat-revoke-dialog/iat-revoke-dialog.component';

@NgModule({
  declarations: [IatAdminComponent, IatIssueDialogComponent, IatPlaintextDialogComponent, IatRevokeDialogComponent],
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    TranslateModule,
    CardModule,
    ClipboardModule,
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatSelectModule,
    MatTableModule,
    MatTooltipModule,
    PaginatorModule,
    TimestampToDatePipeModule,
    LocalizedDatePipeModule,
  ],
  exports: [IatAdminComponent],
})
export default class IatAdminModule {}
