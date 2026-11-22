// ~keep Hand-written ambient stubs for the driver packages the `javascript-*`
// (JSDoc emit mode, #81/#93) backends reference via `import("pkg").Type`
// JSDoc annotations: `postgres` and `bun`.
//
// `tsc --checkJs --strict` (see `validate_javascript_tools` in
// `src/validation.rs`) needs these to resolve those `import("pkg")` type
// queries. The real packages would require `npm install` at test time --
// network-dependent and not reproducible offline -- so these are minimal,
// hand-written approximations, checked in alongside the test that uses them.
//
// They mirror only the call shapes the generated code exercises, and were
// shaped to reproduce (not paper over) the untyped-return behavior that
// produced real `tsc` failures against the genuine packages during #81:
//   - `postgres`'s tagged-template `Sql` call defaults to a concrete `Row`
//     shape (an index signature, not `any`), so `javascript-postgres`'s
//     `:one`/`:many` paths fail to type-check without the
//     `/** @type {Array<T>} */ (...)` cast in
//     `typescript_postgres.rs::generate_query_fn_js`.
//   - `bun`'s `SQL` tagged-template call (copied from `bun-types@1.4.4`'s
//     `sql.d.ts`) defaults its row generic to `any`, so `javascript-bun`'s
//     row cast is harmless rather than required. `TransactionSQL` extends
//     `SQL` with `savepoint`, which `javascript-bun`'s `:batch` casts to
//     when it runs on a transaction's own client.
//
// If either cast is ever dropped, the corresponding
// `test_javascript_*_grouped_and_nullable_pass_real_tools` test in
// `tool_validation.rs` fails against these stubs exactly as it failed
// against the real packages when the defect was first found.

declare module "postgres" {
  export interface Row {
    [column: string]: unknown;
  }
  export interface RowList<T> extends Array<T> {
    count: number;
  }
  export interface Sql {
    <T extends Row = Row>(strings: TemplateStringsArray, ...values: unknown[]): Promise<RowList<T>>;
    begin<T>(callback: (tx: Sql) => Promise<T>): Promise<T>;
  }
}

declare module "bun" {
  export interface ResultMetadata {
    count: number;
  }
  export interface SQL {
    <T = any>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T & ResultMetadata>;
    begin<T>(fn: (sql: TransactionSQL) => Promise<T>): Promise<T>;
    json(value: unknown): unknown;
    array(values: unknown[], typeNameOrTypeID?: number | string): unknown;
  }
  export interface TransactionSQL extends SQL {
    savepoint<T>(fn: (sql: TransactionSQL) => Promise<T>): Promise<T>;
  }
}
