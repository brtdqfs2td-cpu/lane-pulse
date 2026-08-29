import { Client } from "pg";

export interface Env {
  MOTHERDUCK_HOST: string;
  MOTHERDUCK_DB: string;
  MOTHERDUCK_TOKEN: string;
  COACH_API_KEY: string;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function requireCoachAuth(request: Request, env: Env): Response | null {
  const auth = request.headers.get("Authorization") || "";
  const key = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!env.COACH_API_KEY || key !== env.COACH_API_KEY) {
    return json({ error: "unauthorized" }, 401);
  }
  return null;
}

function generateShareToken(): string {
  // 32 random bytes, base64url-encoded -- unguessable, URL-safe
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function createClient(env: Env): Client {
  return new Client({
    connectionString: `postgresql://user:${env.MOTHERDUCK_TOKEN}@${env.MOTHERDUCK_HOST}:5432/${env.MOTHERDUCK_DB}?sslmode=require`,
    connectionTimeoutMillis: 5_000,
    query_timeout: 60_000,
  });
}

// ---------------------------------------------------------------
// POST /practices -- coach pushes a practice + per-swimmer HR summaries
// ---------------------------------------------------------------
interface PracticeSwimmerPayload {
  swimmerId: number;
  avgBpm?: number;
  maxBpm?: number;
  minBpm?: number;
  hrvRmssd?: number;
  zoneSecondsEasy?: number;
  zoneSecondsAerobic?: number;
  zoneSecondsThreshold?: number;
  zoneSecondsMax?: number;
}
interface PracticePayload {
  sessionDate: string; // "YYYY-MM-DD"
  coach?: string;
  location?: string;
  notes?: string;
  startTime?: string; // ISO timestamp
  endTime?: string; // ISO timestamp
  swimmers: PracticeSwimmerPayload[];
}

async function handlePostPractices(request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  let payload: PracticePayload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  if (!payload.sessionDate || !Array.isArray(payload.swimmers) || payload.swimmers.length === 0) {
    return json({ error: "sessionDate and a non-empty swimmers array are required" }, 400);
  }

  const client = createClient(env);
  const createdSessionIds: number[] = [];
  try {
    await client.connect();
    for (const s of payload.swimmers) {
      const sessionResult = await client.query(
        `INSERT INTO swim_sessions (swimmer_id, session_date, coach, location, notes, start_time, end_time)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING session_id`,
        [s.swimmerId, payload.sessionDate, payload.coach ?? null, payload.location ?? null,
         payload.notes ?? null, payload.startTime ?? null, payload.endTime ?? null]
      );
      const sessionId = sessionResult.rows[0].session_id;
      createdSessionIds.push(sessionId);

      await client.query(
        `INSERT INTO swim_hr_data
           (session_id, avg_bpm, max_bpm, min_bpm, hrv_rmssd,
            zone_seconds_easy, zone_seconds_aerobic, zone_seconds_threshold, zone_seconds_max)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [sessionId, s.avgBpm ?? null, s.maxBpm ?? null, s.minBpm ?? null, s.hrvRmssd ?? null,
         s.zoneSecondsEasy ?? null, s.zoneSecondsAerobic ?? null,
         s.zoneSecondsThreshold ?? null, s.zoneSecondsMax ?? null]
      );
    }
    return json({ ok: true, sessionIds: createdSessionIds }, 201);
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// GET /swimmer/:token/summary -- athlete's own read-only view
// ---------------------------------------------------------------
async function handleGetSwimmerSummary(token: string, env: Env): Promise<Response> {
  const client = createClient(env);
  try {
    await client.connect();

    const swimmerResult = await client.query(
      `SELECT swimmer_id, name, baseline_max_hr, baseline_resting_hr, age
       FROM swimmers WHERE share_token = $1 AND is_active = true`,
      [token]
    );
    if (swimmerResult.rows.length === 0) {
      return json({ error: "not found" }, 404);
    }
    const swimmer = swimmerResult.rows[0];

    // TRIMP here is a simplified zone-weighted proxy (Edwards-style: minutes
    // per zone x a linear 1-4 weight), not the strict Banister HRR-based
    // formula -- that needs a reliable resting HR per swimmer, which not
    // everyone has set yet. Good enough for relative session-to-session
    // load comparison, not a precise physiological unit.
    const practicesResult = await client.query(
      `SELECT s.session_id, s.session_date, s.coach, s.location, s.start_time, s.end_time,
              h.avg_bpm, h.max_bpm, h.min_bpm, h.hrv_rmssd,
              h.zone_seconds_easy, h.zone_seconds_aerobic, h.zone_seconds_threshold, h.zone_seconds_max,
              ROUND(
                (COALESCE(h.zone_seconds_easy, 0) / 60.0 * 1) +
                (COALESCE(h.zone_seconds_aerobic, 0) / 60.0 * 2) +
                (COALESCE(h.zone_seconds_threshold, 0) / 60.0 * 3) +
                (COALESCE(h.zone_seconds_max, 0) / 60.0 * 4)
              , 1) AS trimp
       FROM swim_sessions s
       JOIN swim_hr_data h ON h.session_id = s.session_id
       WHERE s.swimmer_id = $1
       ORDER BY s.session_date DESC, s.start_time DESC
       LIMIT 20`,
      [swimmer.swimmer_id]
    );

    const metricsResult = await client.query(
      `SELECT metric_name, value, unit, set_date
       FROM swim_personal_records
       WHERE swimmer_id = $1 AND is_current = true
       ORDER BY metric_name`,
      [swimmer.swimmer_id]
    );

    return json({
      swimmer: {
        name: swimmer.name,
        baselineMaxHr: swimmer.baseline_max_hr,
        baselineRestingHr: swimmer.baseline_resting_hr,
        age: swimmer.age,
      },
      metrics: metricsResult.rows,
      practices: practicesResult.rows,
    });
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// GET /practices -- coach-only, recent synced practices across the whole
// roster (distinct from coach.html's local-only practice history, which
// reads a different, unsynced localStorage record)
// ---------------------------------------------------------------
async function handleGetPractices(request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  const client = createClient(env);
  try {
    await client.connect();
    const result = await client.query(
      `SELECT s.session_id, s.swimmer_id, sw.name AS swimmer_name,
              s.session_date, s.coach, s.location, s.start_time, s.end_time,
              h.avg_bpm, h.max_bpm, h.min_bpm, h.hrv_rmssd,
              h.zone_seconds_easy, h.zone_seconds_aerobic, h.zone_seconds_threshold, h.zone_seconds_max,
              ROUND(
                (COALESCE(h.zone_seconds_easy, 0) / 60.0 * 1) +
                (COALESCE(h.zone_seconds_aerobic, 0) / 60.0 * 2) +
                (COALESCE(h.zone_seconds_threshold, 0) / 60.0 * 3) +
                (COALESCE(h.zone_seconds_max, 0) / 60.0 * 4)
              , 1) AS trimp
       FROM swim_sessions s
       JOIN swimmers sw ON sw.swimmer_id = s.swimmer_id
       LEFT JOIN swim_hr_data h ON h.session_id = s.session_id
       ORDER BY s.session_date DESC, s.start_time DESC
       LIMIT 100`
    );
    return json({ practices: result.rows });
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// GET /roster -- coach-only, full roster + share links
// ---------------------------------------------------------------
async function handleGetRoster(request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  const client = createClient(env);
  try {
    await client.connect();
    const result = await client.query(
      `SELECT swimmer_id, name, share_token, sensor_device_id,
              baseline_max_hr, baseline_resting_hr, age, is_active, created_at
       FROM swimmers
       ORDER BY name`
    );
    const metricsResult = await client.query(
      `SELECT swimmer_id, metric_name, value, unit, set_date
       FROM swim_personal_records
       WHERE is_current = true
       ORDER BY metric_name`
    );
    const metricsBySwimmer: Record<string, unknown[]> = {};
    for (const row of metricsResult.rows) {
      const sid = String(row.swimmer_id);
      if (!metricsBySwimmer[sid]) metricsBySwimmer[sid] = [];
      metricsBySwimmer[sid].push({ metricName: row.metric_name, value: row.value, unit: row.unit, setDate: row.set_date });
    }
    const swimmers = result.rows.map((s) => ({ ...s, metrics: metricsBySwimmer[String(s.swimmer_id)] || [] }));
    return json({ swimmers });
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// POST /roster/swimmers -- coach-only, create a swimmer profile
// ---------------------------------------------------------------
async function handleCreateSwimmer(request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  let body: { name?: string; sensorDeviceId?: string; baselineMaxHr?: number; baselineRestingHr?: number; age?: number };
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  if (!body.name) return json({ error: "name is required" }, 400);

  const shareToken = generateShareToken();
  const client = createClient(env);
  try {
    await client.connect();
    const result = await client.query(
      `INSERT INTO swimmers (name, share_token, sensor_device_id, baseline_max_hr, baseline_resting_hr, age)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING swimmer_id, name, share_token`,
      [body.name, shareToken, body.sensorDeviceId ?? null, body.baselineMaxHr ?? null,
       body.baselineRestingHr ?? null, body.age ?? null]
    );
    return json({ swimmer: result.rows[0] }, 201);
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// PATCH /roster/swimmers/:id -- coach-only, update a swimmer profile
// ---------------------------------------------------------------
async function handleUpdateSwimmer(id: string, request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  let body: { name?: string; sensorDeviceId?: string; baselineMaxHr?: number; baselineRestingHr?: number; age?: number; isActive?: boolean };
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const client = createClient(env);
  try {
    await client.connect();
    const result = await client.query(
      `UPDATE swimmers SET
         name = COALESCE($2, name),
         sensor_device_id = COALESCE($3, sensor_device_id),
         baseline_max_hr = COALESCE($4, baseline_max_hr),
         baseline_resting_hr = COALESCE($5, baseline_resting_hr),
         age = COALESCE($6, age),
         is_active = COALESCE($7, is_active),
         updated_at = current_timestamp
       WHERE swimmer_id = $1
       RETURNING swimmer_id, name, share_token`,
      [id, body.name ?? null, body.sensorDeviceId ?? null, body.baselineMaxHr ?? null,
       body.baselineRestingHr ?? null, body.age ?? null, body.isActive ?? null]
    );
    if (result.rows.length === 0) return json({ error: "not found" }, 404);
    return json({ swimmer: result.rows[0] });
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// POST /roster/swimmers/:id/metrics -- coach-only, log a health metric
// Freeform: any metricName is accepted (e.g. "resting_hr", "vo2_max",
// "body_fat_pct"). Superseding a metric marks the prior current row as
// no-longer-current rather than overwriting it, so history is kept.
// ---------------------------------------------------------------
async function handleAddMetric(swimmerId: string, request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  let body: { metricName?: string; value?: number; unit?: string; setDate?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  if (!body.metricName || body.value === undefined || body.value === null) {
    return json({ error: "metricName and value are required" }, 400);
  }

  const client = createClient(env);
  try {
    await client.connect();
    await client.query(
      `UPDATE swim_personal_records SET is_current = false
       WHERE swimmer_id = $1 AND metric_name = $2 AND is_current = true`,
      [swimmerId, body.metricName]
    );
    const result = await client.query(
      `INSERT INTO swim_personal_records (swimmer_id, metric_name, value, unit, set_date, is_current)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING pr_id, swimmer_id, metric_name, value, unit, set_date`,
      [swimmerId, body.metricName, body.value, body.unit ?? null, body.setDate ?? new Date().toISOString().slice(0, 10)]
    );
    return json({ metric: result.rows[0] }, 201);
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// POST /offline-recordings -- coach-only, store a decoded offline ACC
// recording (already pulled + decoded client-side via the PMD/PSFTP
// stack in offline-recording.js). Samples are stored as a single JSON
// blob rather than one row per sample -- a recording is a few hundred to
// a couple thousand samples, and there's no query pattern yet that needs
// per-sample SQL access, so a blob keeps this simple until one exists.
// ---------------------------------------------------------------
interface OfflineRecordingPayload {
  swimmerId: number;
  recordingPath: string;
  deviceStartTime?: string;
  sampleRateHz?: number;
  frameCount?: number;
  samples: Array<{ timeStamp: string; x: number; y: number; z: number }>;
}

async function handlePostOfflineRecording(request: Request, env: Env): Promise<Response> {
  const authFail = requireCoachAuth(request, env);
  if (authFail) return authFail;

  let payload: OfflineRecordingPayload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  if (!payload.swimmerId || !payload.recordingPath || !Array.isArray(payload.samples) || payload.samples.length === 0) {
    return json({ error: "swimmerId, recordingPath, and a non-empty samples array are required" }, 400);
  }

  const client = createClient(env);
  try {
    await client.connect();
    const result = await client.query(
      `INSERT INTO offline_acc_recordings
         (swimmer_id, recording_path, device_start_time, sample_rate_hz, frame_count, sample_count, samples_json)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING recording_id`,
      [payload.swimmerId, payload.recordingPath, payload.deviceStartTime ?? null,
       payload.sampleRateHz ?? null, payload.frameCount ?? null, payload.samples.length,
       JSON.stringify(payload.samples)]
    );
    return json({ ok: true, recordingId: result.rows[0].recording_id }, 201);
  } catch (err) {
    return json({ error: "database error", detail: String(err) }, 500);
  } finally {
    await client.end();
  }
}

// ---------------------------------------------------------------
// Router
// ---------------------------------------------------------------
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/health" && request.method === "GET") {
      return json({ status: "ok" });
    }
    if (path === "/practices" && request.method === "POST") {
      return handlePostPractices(request, env);
    }
    if (path === "/practices" && request.method === "GET") {
      return handleGetPractices(request, env);
    }
    if (path === "/roster" && request.method === "GET") {
      return handleGetRoster(request, env);
    }
    if (path === "/roster/swimmers" && request.method === "POST") {
      return handleCreateSwimmer(request, env);
    }
    const swimmerPatchMatch = path.match(/^\/roster\/swimmers\/(\d+)$/);
    if (swimmerPatchMatch && request.method === "PATCH") {
      return handleUpdateSwimmer(swimmerPatchMatch[1], request, env);
    }
    const metricsMatch = path.match(/^\/roster\/swimmers\/(\d+)\/metrics$/);
    if (metricsMatch && request.method === "POST") {
      return handleAddMetric(metricsMatch[1], request, env);
    }
    if (path === "/offline-recordings" && request.method === "POST") {
      return handlePostOfflineRecording(request, env);
    }
    const summaryMatch = path.match(/^\/swimmer\/([^/]+)\/summary$/);
    if (summaryMatch && request.method === "GET") {
      return handleGetSwimmerSummary(decodeURIComponent(summaryMatch[1]), env);
    }

    return json({ error: "not found" }, 404);
  },
};
