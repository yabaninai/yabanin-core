package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/auth"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/labels"
)

const (
	sessionMintDefaultTTL = 7200
	sessionMintMinTTL     = 60
	sessionMintMaxTTL     = 43200
	sessionMintPerMinute  = 60
	sessionBodyLimit      = 16 * 1024
	sessionUsageMaxSpan   = 31 * 24 * time.Hour
)

var sessionNamePattern = regexp.MustCompile(`^[A-Za-z0-9 ._:/-]{0,64}$`)

// sessionQuerier is the database slice for session-key endpoints.
// *pgxpool.Pool satisfies it. Nil answers 501.
type sessionQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (gw *gateway) sessions() sessionQuerier {
	if gw.sessionDB != nil {
		return gw.sessionDB
	}
	if gw.dbPool == nil {
		return nil
	}
	return gw.dbPool
}

func (gw *gateway) requireSessions(w http.ResponseWriter, r *http.Request) sessionQuerier {
	db := gw.sessions()
	if db == nil {
		apierrors.Write(w, http.StatusNotImplemented, "session_keys_unavailable", "session keys require a database")
		return nil
	}
	_ = r
	return db
}

type sessionMintBody struct {
	Name       string            `json:"name"`
	TTL        *int              `json:"ttl_seconds"`
	Labels     map[string]string `json:"labels"`
	LockLabels bool              `json:"lock_labels"`
	MaxTokens  *int64            `json:"max_tokens"`
	MaxCostUSD *float64          `json:"max_cost_usd"`
}

func (gw *gateway) mintSessionKey(w http.ResponseWriter, r *http.Request) {
	db := gw.requireSessions(w, r)
	if db == nil {
		return
	}
	p, ok := principalFrom(r.Context())
	if !ok || p.AgentID != "" || p.SessionKeyID != "" || !p.CanMintSessions || p.APIKeyID == "" {
		apierrors.Write(w, http.StatusForbidden, "session_mint_not_allowed", "this key cannot mint session keys")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sessionBodyLimit))
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req sessionMintBody
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierrors.Write(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if !sessionNamePattern.MatchString(req.Name) {
		apierrors.Write(w, http.StatusBadRequest, "invalid_name", "name must match [A-Za-z0-9 ._:/-] and be at most 64 characters")
		return
	}
	ttl := sessionMintDefaultTTL
	if req.TTL != nil {
		ttl = *req.TTL
		if ttl < sessionMintMinTTL || ttl > sessionMintMaxTTL {
			apierrors.Write(w, http.StatusBadRequest, "invalid_ttl", "ttl_seconds must be between 60 and 43200")
			return
		}
	}
	if req.MaxTokens != nil && (*req.MaxTokens < 1 || *req.MaxTokens > 10_000_000_000) {
		apierrors.Write(w, http.StatusBadRequest, "invalid_limits", "max_tokens must be between 1 and 10000000000")
		return
	}
	if req.MaxCostUSD != nil && (*req.MaxCostUSD <= 0 || *req.MaxCostUSD > 1_000_000) {
		apierrors.Write(w, http.StatusBadRequest, "invalid_limits", "max_cost_usd must be greater than 0 and at most 1000000")
		return
	}
	orgID := r.Header.Get("X-Org-Id")
	compiled := gw.labelPolicyFor(r.Context(), orgID)
	merged := labels.Resolve(compiled, append(principalLabelSources(r.Context()), labels.Source{
		Name: "session", Labels: req.Labels, Locked: req.LockLabels,
	}), labelSecret)
	if merged.Rejected {
		apierrors.Write(w, http.StatusBadRequest, merged.RejectCode, droppedKeys(merged.Dropped))
		return
	}
	if !gw.allowSessionMint(r.Context(), p.APIKeyID) {
		apierrors.Write(w, http.StatusTooManyRequests, "rate_limited", "session key mint rate exceeded")
		return
	}
	plaintext, err := auth.GenerateSessionKey()
	if err != nil {
		apierrors.Write(w, http.StatusInternalServerError, "session_mint_failed", "could not mint a session key")
		return
	}
	stored := acceptedBodyLabels(req.Labels, merged)
	raw, err := json.Marshal(stored)
	if err != nil {
		apierrors.Write(w, http.StatusInternalServerError, "session_mint_failed", "could not mint a session key")
		return
	}
	expires := time.Now().UTC().Add(time.Duration(ttl) * time.Second)
	// AUTH-03: a session must never outlive its parent API key. When the
	// parent has a finite expiry, the minted session's TTL is capped at it —
	// otherwise a key expiring within minutes could mint sessions valid for
	// hours that the resolver keeps accepting after the parent is gone.
	if !p.KeyExpiresAt.IsZero() && p.KeyExpiresAt.Before(expires) {
		expires = p.KeyExpiresAt.UTC()
		if expires.Before(time.Now().UTC()) {
			apierrors.Write(w, http.StatusBadRequest, "parent_key_expired",
				"parent API key is expired; cannot mint a session key")
			return
		}
	}
	var id string
	err = db.QueryRow(r.Context(),
		`INSERT INTO session_keys
		    (key_hash, org_id, parent_api_key_id, name, labels, labels_locked, max_tokens, max_cost_usd, expires_at)
		  VALUES ($1, $2::uuid, $3::uuid, $4, $5::jsonb, $6, $7, $8, $9)
		  RETURNING id::text`,
		auth.HashKey(plaintext), orgID, p.APIKeyID, req.Name, raw, req.LockLabels, req.MaxTokens, req.MaxCostUSD, expires,
	).Scan(&id)
	if err != nil {
		gw.log.Warn("session key insert failed", "error", err, "parent", p.APIKeyID)
		apierrors.Write(w, http.StatusInternalServerError, "session_mint_failed", "could not mint a session key")
		return
	}
	gw.log.Info("session key minted", "id", id, "parent", p.APIKeyID, "ttl", ttl)
	writeJSONCode(w, http.StatusCreated, map[string]any{
		"id": id, "key": plaintext, "expires_at": expires.Format(time.RFC3339),
		"labels": merged.Labels, "dropped": merged.Dropped,
	})
}

func acceptedBodyLabels(body map[string]string, merged labels.Result) map[string]string {
	out := map[string]string{}
	dropped := map[string]bool{}
	for _, item := range merged.Dropped {
		dropped[item.Key] = true
	}
	for raw := range body {
		key, ok := labels.NormalizeKey(raw)
		if !ok || dropped[key] {
			continue
		}
		if value, ok := merged.Labels[key]; ok {
			out[key] = value
		}
	}
	return out
}

func (gw *gateway) allowSessionMint(ctx context.Context, parentID string) bool {
	kv := gw.sessionRedisClient()
	if kv == nil {
		gw.log.Warn("session mint rate limit skipped; redis unavailable", "parent", parentID)
		return true
	}
	key := fmt.Sprintf("yb:skey:mint:%s:%d", parentID, time.Now().Unix()/60)
	n, err := kv.Incr(ctx, key).Result()
	if err != nil {
		gw.log.Warn("session mint rate limit skipped; redis unavailable", "error", err, "parent", parentID)
		return true
	}
	if n == 1 {
		_ = kv.Expire(ctx, key, 120*time.Second).Err()
	}
	return n <= sessionMintPerMinute
}

type sessionRow struct {
	id         string
	parentID   string
	keyHash    string
	orgID      string
	revokedAt  *time.Time
	finishedAt *time.Time
}

func (gw *gateway) loadSession(ctx context.Context, db sessionQuerier, id string) (sessionRow, error) {
	var row sessionRow
	err := db.QueryRow(ctx,
		`SELECT id::text, parent_api_key_id::text, key_hash, org_id::text, revoked_at, finished_at
		   FROM session_keys WHERE id = $1`, id,
	).Scan(&row.id, &row.parentID, &row.keyHash, &row.orgID, &row.revokedAt, &row.finishedAt)
	// The only input to this query is the UUID from the URL.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "22P02" {
		return sessionRow{}, pgx.ErrNoRows
	}
	return row, err
}

func sessionVisible(p principal, row sessionRow) bool {
	if p.SessionKeyID != "" {
		return p.SessionKeyID == row.id
	}
	return p.APIKeyID != "" && p.APIKeyID == row.parentID
}

func (gw *gateway) revokeSessionKey(w http.ResponseWriter, r *http.Request) {
	db := gw.requireSessions(w, r)
	if db == nil {
		return
	}
	p, _ := principalFrom(r.Context())
	row, err := gw.loadSession(r.Context(), db, chi.URLParam(r, "id"))
	if err != nil || !sessionVisible(p, row) {
		apierrors.Write(w, http.StatusNotFound, "not_found", "session key not found")
		return
	}
	if row.revokedAt == nil {
		if _, err := db.Exec(r.Context(),
			`UPDATE session_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, row.id); err != nil {
			apierrors.Write(w, http.StatusInternalServerError, "session_revoke_failed", "could not revoke the session key")
			return
		}
		gw.purgeSessionCache(r.Context(), row.keyHash)
	}
	w.WriteHeader(http.StatusNoContent)
}

type sessionFinishBody struct {
	Status     string `json:"status"`
	ExitCode   *int   `json:"exit_code"`
	DurationMs *int64 `json:"duration_ms"`
}

func (gw *gateway) finishSessionKey(w http.ResponseWriter, r *http.Request) {
	db := gw.requireSessions(w, r)
	if db == nil {
		return
	}
	p, _ := principalFrom(r.Context())
	row, err := gw.loadSession(r.Context(), db, chi.URLParam(r, "id"))
	if err != nil || !sessionVisible(p, row) {
		apierrors.Write(w, http.StatusNotFound, "not_found", "session key not found")
		return
	}
	if row.finishedAt != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sessionBodyLimit))
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req sessionFinishBody
	if err := dec.Decode(&req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	switch req.Status {
	case "success", "failed", "canceled":
	default:
		apierrors.Write(w, http.StatusBadRequest, "invalid_request", "status must be success, failed, or canceled")
		return
	}
	tag, err := db.Exec(r.Context(),
		`UPDATE session_keys
		    SET outcome = $2, exit_code = $3, duration_ms = $4, finished_at = now(), revoked_at = COALESCE(revoked_at, now())
		  WHERE id = $1 AND finished_at IS NULL`,
		row.id, req.Status, req.ExitCode, req.DurationMs)
	if err != nil {
		apierrors.Write(w, http.StatusInternalServerError, "session_finish_failed", "could not finish the session key")
		return
	}
	if tag.RowsAffected() > 0 {
		gw.purgeSessionCache(r.Context(), row.keyHash)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (gw *gateway) purgeSessionCache(ctx context.Context, keyHash string) {
	if keyHash == "" {
		return
	}
	kv := gw.sessionRedisClient()
	if kv == nil {
		return
	}
	if err := kv.Del(ctx, "org:resolve:"+keyHash).Err(); err != nil {
		gw.log.Warn("session resolver cache purge failed", "error", err)
	}
}

type usageTotals struct {
	Requests  int64        `json:"requests"`
	TokensIn  int64        `json:"tokens_in"`
	TokensOut int64        `json:"tokens_out"`
	CacheRead int64        `json:"cache_read_tokens"`
	CostUSD   float64      `json:"cost_usd"`
	Unpriced  int64        `json:"unpriced_requests"`
	ByModel   []usageModel `json:"by_model"`
	Complete  bool         `json:"complete"`
	Groups    []usageGroup `json:"groups,omitempty"`
}

type usageModel struct {
	Model     string  `json:"model"`
	Requests  int64   `json:"requests"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
}

type usageGroup struct {
	Value     string  `json:"value"`
	Requests  int64   `json:"requests"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
}

func (gw *gateway) sessionKeyUsage(w http.ResponseWriter, r *http.Request) {
	db := gw.requireSessions(w, r)
	if db == nil {
		return
	}
	p, _ := principalFrom(r.Context())
	row, err := gw.loadSession(r.Context(), db, chi.URLParam(r, "id"))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		gw.usageUnavailable(w, err)
		return
	}
	if err != nil || !sessionVisible(p, row) {
		apierrors.Write(w, http.StatusNotFound, "not_found", "session key not found")
		return
	}
	totals, err := queryUsage(r.Context(), db,
		`SELECT count(*), COALESCE(sum(tokens_in),0), COALESCE(sum(tokens_out),0),
		        COALESCE(sum(COALESCE(cache_read_tokens,0)),0),
		        COALESCE(sum(cost_in_usd) FILTER (WHERE cost_status IN ('priced','cache_hit','legacy')),0),
		        count(*) FILTER (WHERE cost_status IN ('unknown_price','no_usage'))
		   FROM request_logs
		  WHERE org_id = $1 AND session_key_id = $2 AND COALESCE(ab_group,'') <> 'shadow'`,
		row.orgID, row.id)
	if err != nil {
		gw.usageUnavailable(w, err)
		return
	}
	totals.ByModel, err = queryUsageModels(r.Context(), db,
		`SELECT model_used, count(*), COALESCE(sum(tokens_in),0), COALESCE(sum(tokens_out),0),
		        COALESCE(sum(cost_in_usd) FILTER (WHERE cost_status IN ('priced','cache_hit','legacy')),0)
		   FROM request_logs
		  WHERE org_id = $1 AND session_key_id = $2 AND COALESCE(ab_group,'') <> 'shadow'
		  GROUP BY model_used`, row.orgID, row.id)
	if err != nil {
		gw.usageUnavailable(w, err)
		return
	}
	totals.Complete = row.finishedAt != nil && time.Since(*row.finishedAt) >= 10*time.Second
	writeJSONCode(w, http.StatusOK, totals)
}

func (gw *gateway) ownUsage(w http.ResponseWriter, r *http.Request) {
	db := gw.requireSessions(w, r)
	if db == nil {
		return
	}
	p, ok := principalFrom(r.Context())
	if !ok || !p.CanReadUsage || p.APIKeyID == "" || p.SessionKeyID != "" {
		apierrors.Write(w, http.StatusForbidden, "usage_read_not_allowed", "this key cannot read usage")
		return
	}
	params, err := parseOwnUsageParams(r.URL.RawQuery)
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	totals, err := queryOwnUsageReport(r.Context(), db, r.Header.Get("X-Org-Id"), p.APIKeyID, params)
	if err != nil {
		gw.usageUnavailable(w, err)
		return
	}
	writeJSONCode(w, http.StatusOK, totals)
}

func queryOwnUsageReport(ctx context.Context, db sessionQuerier, orgID, keyID string, params ownUsageParams) (usageTotals, error) {
	from, to, rawFilter := params.from, params.to, params.filter
	var groups []usageGroup
	if params.groupExpr != "" {
		var err error
		groups, err = queryUsageGroups(ctx, db, params.groupExpr, orgID, keyID, from, to, rawFilter)
		if err != nil {
			return usageTotals{}, err
		}
	}
	totals, err := queryUsage(ctx, db,
		`SELECT count(*), COALESCE(sum(tokens_in),0), COALESCE(sum(tokens_out),0),
		        COALESCE(sum(COALESCE(cache_read_tokens,0)),0),
		        COALESCE(sum(cost_in_usd) FILTER (WHERE cost_status IN ('priced','cache_hit','legacy')),0),
		        count(*) FILTER (WHERE cost_status IN ('unknown_price','no_usage'))
		   FROM request_logs
		  WHERE org_id = $1 AND api_key_id = $2 AND created_at >= $3 AND created_at < $4
		    AND COALESCE(ab_group,'') <> 'shadow' AND labels @> $5::jsonb`,
		orgID, keyID, from, to, rawFilter)
	if err != nil {
		return usageTotals{}, err
	}
	totals.ByModel, err = queryUsageModels(ctx, db,
		`SELECT model_used, count(*), COALESCE(sum(tokens_in),0), COALESCE(sum(tokens_out),0),
		        COALESCE(sum(cost_in_usd) FILTER (WHERE cost_status IN ('priced','cache_hit','legacy')),0)
		   FROM request_logs
		  WHERE org_id = $1 AND api_key_id = $2 AND created_at >= $3 AND created_at < $4
		    AND COALESCE(ab_group,'') <> 'shadow' AND labels @> $5::jsonb
		  GROUP BY model_used`,
		orgID, keyID, from, to, rawFilter)
	if err != nil {
		return usageTotals{}, err
	}
	totals.Groups = groups
	totals.Complete = !to.After(time.Now().Add(-10 * time.Second))
	return totals, nil
}

type ownUsageParams struct {
	from, to  time.Time
	filter    []byte
	groupExpr string
}

func parseOwnUsageParams(raw string) (ownUsageParams, error) {
	var p ownUsageParams
	query, err := url.ParseQuery(raw)
	if err != nil {
		return p, errors.New("invalid usage query encoding")
	}
	p.from, p.to, err = ownUsageTimeRange(query)
	if err != nil {
		return p, err
	}
	filter := map[string]string{}
	for key, values := range query {
		name, ok := strings.CutPrefix(key, "label.")
		if !ok || name == "" || len(values) == 0 {
			continue
		}
		norm, valid := labels.NormalizeKey(name)
		if !valid {
			return p, errors.New("label filter key is not valid")
		}
		filter[norm] = values[0]
	}
	// filter is map[string]string: every Go string is JSON-encodable
	// (invalid UTF-8 coerces to U+FFFD), so Marshal cannot fail.
	p.filter, _ = json.Marshal(filter)
	if group := query.Get("group_by"); group != "" {
		p.groupExpr, err = usageGroupExpression(group)
	}
	return p, err
}

func ownUsageTimeRange(query url.Values) (time.Time, time.Time, error) {
	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	if raw := query.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("from must be RFC3339")
		}
		from = parsed.UTC()
	}
	if raw := query.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("to must be RFC3339")
		}
		to = parsed.UTC()
	}
	if !to.After(from) || to.Sub(from) > sessionUsageMaxSpan {
		return time.Time{}, time.Time{}, errors.New("range must be at most 31 days")
	}
	return from, to, nil
}

func (gw *gateway) usageUnavailable(w http.ResponseWriter, err error) {
	gw.log.Warn("usage report unavailable", "error", err)
	apierrors.Write(w, http.StatusServiceUnavailable, "usage_unavailable", "usage report is temporarily unavailable")
}

func queryUsage(ctx context.Context, db sessionQuerier, sql string, args ...any) (usageTotals, error) {
	var out usageTotals
	err := db.QueryRow(ctx, sql, args...).Scan(&out.Requests, &out.TokensIn, &out.TokensOut, &out.CacheRead, &out.CostUSD, &out.Unpriced)
	return out, err
}

func queryUsageModels(ctx context.Context, db sessionQuerier, sql string, args ...any) ([]usageModel, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (usageModel, error) {
		var item usageModel
		err := row.Scan(&item.Model, &item.Requests, &item.TokensIn, &item.TokensOut, &item.CostUSD)
		return item, err
	})
}

func usageGroupExpression(group string) (string, error) {
	if group == "model" {
		return "model_used", nil
	}
	key, ok := strings.CutPrefix(group, "label:")
	if !ok {
		return "", fmt.Errorf("group_by must be model or label:<key>")
	}
	key, ok = labels.NormalizeKey(key)
	if !ok {
		return "", fmt.Errorf("group_by label key is not valid")
	}
	return "labels->>" + quoteLiteral(key), nil
}

func queryUsageGroups(ctx context.Context, db sessionQuerier, expr, orgID, apiKeyID string, from, to time.Time, filter []byte) ([]usageGroup, error) {
	sql := `SELECT ` + expr + `, count(*), COALESCE(sum(tokens_in),0), COALESCE(sum(tokens_out),0),
	        COALESCE(sum(cost_in_usd) FILTER (WHERE cost_status IN ('priced','cache_hit','legacy')),0)
	   FROM request_logs
	  WHERE org_id = $1 AND api_key_id = $2 AND created_at >= $3 AND created_at < $4
	    AND COALESCE(ab_group,'') <> 'shadow' AND labels @> $5::jsonb
	  GROUP BY 1`
	rows, err := db.Query(ctx, sql, orgID, apiKeyID, from, to, filter)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (usageGroup, error) {
		var item usageGroup
		var value *string
		err := row.Scan(&value, &item.Requests, &item.TokensIn, &item.TokensOut, &item.CostUSD)
		if value != nil {
			item.Value = *value
		}
		return item, err
	})
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (gw *gateway) sessionLabelPolicy(w http.ResponseWriter, r *http.Request) {
	db := gw.requireSessions(w, r)
	if db == nil {
		return
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication, "org resolution failed")
		return
	}
	_ = gw.labelPolicyFor(r.Context(), orgID)
	var raw []byte
	err := db.QueryRow(r.Context(), `SELECT policy FROM label_policies WHERE org_id = $1`, orgID).Scan(&raw)
	if err != nil || len(raw) == 0 {
		writeJSONCode(w, http.StatusOK, labels.DefaultPolicy())
		return
	}
	var policy labels.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		writeJSONCode(w, http.StatusOK, labels.DefaultPolicy())
		return
	}
	writeJSONCode(w, http.StatusOK, policy)
}

func writeJSONCode(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
