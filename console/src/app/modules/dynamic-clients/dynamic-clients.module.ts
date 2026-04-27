import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterModule } from '@angular/router';
import { TranslateModule } from '@ngx-translate/core';
import { CardModule } from 'src/app/modules/card/card.module';
import { LocalizedDatePipeModule } from 'src/app/pipes/localized-date-pipe/localized-date-pipe.module';
import { TimestampToDatePipeModule } from 'src/app/pipes/timestamp-to-date-pipe/timestamp-to-date-pipe.module';

import { DynamicClientsComponent } from './dynamic-clients.component';

@NgModule({
  declarations: [DynamicClientsComponent],
  imports: [
    CommonModule,
    RouterModule,
    TranslateModule,
    CardModule,
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatTooltipModule,
    TimestampToDatePipeModule,
    LocalizedDatePipeModule,
  ],
  exports: [DynamicClientsComponent],
})
export default class DynamicClientsModule {}
