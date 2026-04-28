import { Component, Input, OnChanges, SimpleChanges } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { App } from 'src/app/proto/generated/zitadel/app_pb';
import { ManagementService } from 'src/app/services/mgmt.service';
import { ToastService } from 'src/app/services/toast.service';

interface DcrClientRow {
  id: string;
  name: string;
  registrationMethod: 'ANONYMOUS' | 'IAT';
  creationDate?: { seconds: number; nanos: number };
}

@Component({
  selector: 'cnsl-dynamic-clients',
  templateUrl: './dynamic-clients.component.html',
  styleUrls: ['./dynamic-clients.component.scss'],
  standalone: false,
})
export class DynamicClientsComponent implements OnChanges {
  @Input() public projectId: string = '';

  public readonly displayedColumns: string[] = ['clientId', 'clientName', 'registrationMethod', 'creationDate', 'audit'];
  public readonly clients$ = new BehaviorSubject<DcrClientRow[]>([]);
  public readonly loading$ = new BehaviorSubject<boolean>(false);

  constructor(
    private readonly mgmt: ManagementService,
    private readonly toast: ToastService,
  ) {}

  public ngOnChanges(changes: SimpleChanges): void {
    if (changes['projectId'] && this.projectId) {
      this.load();
    }
  }

  private load(): void {
    if (this.loading$.value) {
      return;
    }
    this.loading$.next(true);
    this.mgmt
      .listApps(this.projectId, 100, 0)
      .then((resp) => {
        const rows = (resp.resultList ?? [])
          .filter((app) => isDynamicallyRegistered(app))
          .map<DcrClientRow>((app) => ({
            id: app.id,
            name: app.name,
            registrationMethod: registrationMethodFor(app),
            creationDate: app.details?.creationDate,
          }));
        this.clients$.next(rows);
      })
      .catch((err) => this.toast.showError(err))
      .finally(() => this.loading$.next(false));
  }
}

// Phase 1 gap: the App proto exposes no DCR-specific marker (no dcr_meta,
// no registration_access_token_hash, no registration_method). Until the
// proto is extended to carry those fields, the predicate has nothing to
// match on and the listing renders the empty state. The component shape,
// columns, sidenav placement, and audit-link routing are in place so the
// switchover is a one-line change once the proto lands. Tracked as a
// follow-up: "expose DCR registration metadata in management App proto".
function isDynamicallyRegistered(_app: App.AsObject): boolean {
  return false;
}

function registrationMethodFor(_app: App.AsObject): 'ANONYMOUS' | 'IAT' {
  return 'ANONYMOUS';
}
