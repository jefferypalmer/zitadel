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

// T-104 (Tier 9, 2026-04-28): the App proto now carries
// `OIDCConfig.dynamicallyRegistered` (T-100), surfaced from
// `apps7_oidc_configs.registration_access_token_hash IS NOT NULL` via
// `query.OIDCApp.IsDynamicallyRegistered` (T-101) and populated through
// the management converter (T-102). Predicate is now a one-liner.
function isDynamicallyRegistered(app: App.AsObject): boolean {
  return app.oidcConfig?.dynamicallyRegistered === true;
}

// Registration-method discrimination (anonymous vs IAT-derived) is not
// yet exposed by the App proto. The `registration_method` audit-event
// field landed in T-040 but is not on the projection. For now, both
// rows render under the ANONYMOUS bucket; a follow-up can split them
// by adding a `registration_method` enum field to the App proto.
function registrationMethodFor(_app: App.AsObject): 'ANONYMOUS' | 'IAT' {
  return 'ANONYMOUS';
}
