import { DataSource } from '@angular/cdk/collections';
import { Timestamp } from 'google-protobuf/google/protobuf/timestamp_pb';
import { BehaviorSubject, from, Observable, of } from 'rxjs';
import { catchError, finalize, map } from 'rxjs/operators';
import { App } from 'src/app/proto/generated/zitadel/app_pb';
import { ManagementService } from 'src/app/services/mgmt.service';

/**
 * Data source for the ProjectMembers view. This class should
 * encapsulate all logic for fetching and manipulating the displayed data
 * (including sorting, pagination, and filtering).
 *
 * Dynamically-registered (RFC 7591) clients are filtered out at the
 * datasource level — they are surfaced separately under the
 * "Dynamic Clients" sidenav peer (see
 * cavekit-dcr-bootstrap-validation.md R11). The mgmt gRPC `ListApps`
 * RPC continues to return both kinds; the filter is UI-only so a
 * project hosting hundreds of MCP-registered clients doesn't drown
 * out operator-created apps in the General tab.
 */
export class ProjectApplicationsDataSource extends DataSource<App.AsObject> {
  public totalResult: number = 0;
  public viewTimestamp!: Timestamp.AsObject;

  public appsSubject: BehaviorSubject<App.AsObject[]> = new BehaviorSubject<App.AsObject[]>([]);
  // hiddenCountSubject reports how many dynamically-registered clients
  // were dropped from the most recent page so the table view can render
  // an info banner with a click-through to the Dynamic Clients sidenav
  // setting (cavekit-dcr-bootstrap-validation.md R11).
  public hiddenCountSubject: BehaviorSubject<number> = new BehaviorSubject<number>(0);
  private loadingSubject: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
  public loading$: Observable<boolean> = this.loadingSubject.asObservable();

  constructor(private mgmtService: ManagementService) {
    super();
  }

  public loadApps(projectId: string, pageIndex: number, pageSize: number): void {
    const offset = pageIndex * pageSize;

    this.loadingSubject.next(true);
    from(this.mgmtService.listApps(projectId, pageSize, offset))
      .pipe(
        map((resp) => {
          const response = resp;
          if (response.details?.totalResult) {
            this.totalResult = response.details.totalResult;
          }
          if (response.details?.viewTimestamp) {
            this.viewTimestamp = response.details.viewTimestamp;
          }
          return response.resultList;
        }),
        catchError(() => of([])),
        finalize(() => this.loadingSubject.next(false)),
      )
      .subscribe((apps) => {
        const visible = apps.filter((app) => app?.oidcConfig?.dynamicallyRegistered !== true);
        const hiddenCount = apps.length - visible.length;
        this.hiddenCountSubject.next(hiddenCount);
        this.appsSubject.next(visible);
      });
  }

  /**
   * Connect this data source to the table. The table will only update when
   * the returned stream emits new items.
   * @returns A stream of the items to be rendered.
   */
  public connect(): Observable<App.AsObject[]> {
    return this.appsSubject.asObservable();
  }

  /**
   *  Called when the table is being destroyed. Use this function, to clean up
   * any open connections or free any held resources that were set up during connect.
   */
  public disconnect(): void {
    this.appsSubject.complete();
    this.hiddenCountSubject.complete();
    this.loadingSubject.complete();
  }
}
