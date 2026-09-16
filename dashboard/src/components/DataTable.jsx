import React from 'react';
import { ChevronDown, ChevronUp, ChevronsUpDown, Loader2 } from 'lucide-react';

/**
 * Reusable dark-mode DataTable component.
 *
 * Props:
 *   columns: Array<{ key: string, label: string, sortable?: boolean, render?: (val, row) => ReactNode, width?: string }>
 *   data: Array<any>
 *   loading?: boolean
 *   emptyMessage?: string
 *   onRowClick?: (row: any) => void
 *   sortField?: string
 *   sortDir?: 'asc' | 'desc'
 *   onSort?: (field: string) => void
 *   pagination?: { page: number, pageSize: number, total: number, onPageChange: (p: number) => void }
 */
export default function DataTable({
  columns = [],
  data = [],
  loading = false,
  emptyMessage = 'No records found',
  onRowClick,
  sortField,
  sortDir = 'desc',
  onSort,
  pagination,
}) {
  const totalPages = pagination ? Math.ceil(pagination.total / pagination.pageSize) : 1;

  return (
    <div className="table-container">
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((col) => {
                const isSorted = sortField === col.key;
                return (
                  <th
                    key={col.key}
                    style={{ width: col.width || 'auto' }}
                    className={col.sortable ? 'sortable' : ''}
                    onClick={() => col.sortable && onSort && onSort(col.key)}
                  >
                    <div className="th-content">
                      <span>{col.label}</span>
                      {col.sortable && (
                        <span className="sort-icon">
                          {isSorted ? (
                            sortDir === 'asc' ? (
                              <ChevronUp size={14} className="text-accent-cyan" />
                            ) : (
                              <ChevronDown size={14} className="text-accent-cyan" />
                            )
                          ) : (
                            <ChevronsUpDown size={14} className="text-muted opacity-40" />
                          )}
                        </span>
                      )}
                    </div>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={columns.length} className="table-empty">
                  <div className="loading-spinner">
                    <Loader2 size={24} className="animate-spin text-accent-blue" />
                    <span>Loading data...</span>
                  </div>
                </td>
              </tr>
            ) : data.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="table-empty">
                  <div className="empty-state-content">
                    <p className="empty-text">{emptyMessage}</p>
                  </div>
                </td>
              </tr>
            ) : (
              data.map((row, idx) => (
                <tr
                  key={row.id || row.agent_id || row.name || idx}
                  onClick={() => onRowClick && onRowClick(row)}
                  className={onRowClick ? 'clickable-row' : ''}
                >
                  {columns.map((col) => (
                    <td key={col.key}>
                      {col.render ? col.render(row[col.key], row) : row[col.key] ?? '—'}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pagination && totalPages > 1 && (
        <div className="table-pagination">
          <span className="pagination-info">
            Showing {Math.min((pagination.page - 1) * pagination.pageSize + 1, pagination.total)} to{' '}
            {Math.min(pagination.page * pagination.pageSize, pagination.total)} of {pagination.total} entries
          </span>
          <div className="pagination-controls">
            <button
              type="button"
              className="btn-pagination"
              disabled={pagination.page <= 1}
              onClick={() => pagination.onPageChange(pagination.page - 1)}
            >
              Previous
            </button>
            <span className="page-indicator">
              Page {pagination.page} of {totalPages}
            </span>
            <button
              type="button"
              className="btn-pagination"
              disabled={pagination.page >= totalPages}
              onClick={() => pagination.onPageChange(pagination.page + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
