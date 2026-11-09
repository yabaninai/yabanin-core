// W-FEED: the owner feedback surface (GET /api/feedback + the CSV export,
// both MustBeRoot). The endpoint lists POST /v1/feedback records
// (classifier_feedback) with org/rating filters; the export rides the same
// filters and always returns the full filtered set as RFC 4180 CSV.

import { fetchJSON, listQuery, DEFAULT_PAGE_SIZE, type ListSortParams, type RequestOptions } from './http.ts'

export interface FeedbackEntry {
  id: number
  org_id: string
  request_id: string
  prompt_hash: string
  original_class: string
  action: 'thumbs_up' | 'thumbs_down' | 'regenerate'
  created_at: string
}

export interface FeedbackPage {
  feedback: FeedbackEntry[]
  total: number
  page: number
  page_size: number
}

export interface FeedbackListParams {
  orgId?: string
  rating?: string
  page?: number
  pageSize?: number
}

function feedbackQuery(params: FeedbackListParams): string {
  const q = new URLSearchParams(listQuery(params.page ?? 1, params.pageSize ?? DEFAULT_PAGE_SIZE))
  if (params.orgId) q.set('org_id', params.orgId)
  if (params.rating) q.set('rating', params.rating)
  return q.toString()
}

export async function listFeedback(params: FeedbackListParams = {}, opts?: RequestOptions & ListSortParams): Promise<FeedbackPage> {
  return fetchJSON(`/feedback?${feedbackQuery(params)}`, opts)
}

// Same filters as the list; the server ignores pagination on exports, so the
// CSV is always the full filtered set. Rendered as a download link href.
export function feedbackExportUrl(params: FeedbackListParams = {}): string {
  return `/api/feedback/export?${feedbackQuery({ ...params, page: 1, pageSize: DEFAULT_PAGE_SIZE })}`
}
