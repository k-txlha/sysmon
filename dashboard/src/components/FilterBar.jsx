import React from 'react';
import { Search, RotateCcw, Filter } from 'lucide-react';

/**
 * Reusable filter toolbar.
 *
 * Props:
 *   searchValue?: string
 *   onSearchChange?: (val: string) => void
 *   searchPlaceholder?: string
 *   filters?: Array<{
 *     id: string,
 *     label: string,
 *     value: any,
 *     options: Array<{ value: any, label: string }>,
 *     onChange: (val: any) => void
 *   }>
 *   onReset?: () => void
 *   actions?: ReactNode
 */
export default function FilterBar({
  searchValue = '',
  onSearchChange,
  searchPlaceholder = 'Search...',
  filters = [],
  onReset,
  actions,
}) {
  return (
    <div className="filter-bar">
      <div className="filter-group-left">
        {onSearchChange && (
          <div className="search-input-wrapper">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder={searchPlaceholder}
              value={searchValue}
              onChange={(e) => onSearchChange(e.target.value)}
            />
          </div>
        )}

        {filters.map((f) => (
          <div key={f.id} className="filter-select-wrapper">
            <select
              className="filter-select"
              value={f.value}
              onChange={(e) => f.onChange(e.target.value)}
            >
              <option value="">{f.label}</option>
              {f.options.map((opt) => (
                <option key={String(opt.value)} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        ))}

        {onReset && (
          <button
            type="button"
            className="btn-icon"
            title="Reset filters"
            onClick={onReset}
          >
            <RotateCcw size={15} />
          </button>
        )}
      </div>

      {actions && <div className="filter-group-right">{actions}</div>}
    </div>
  );
}
