/**
 * api.ts — centralised HTTP client for Doctor Booked backend
 *
 * Drop this file into src/frontend/src/api.ts
 * Then update StoreContext to use these functions instead of localStorage.
 */

const BASE = import.meta.env.VITE_API_URL || "http://localhost:4000/api";
const WS_BASE = (import.meta.env.VITE_API_URL || "http://localhost:4000")
  .replace(/^http/, "ws");

// ── Token storage ─────────────────────────────────────────────────────────────
export function getToken(): string | null {
  return localStorage.getItem("db_jwt");
}
export function setToken(t: string) {
  localStorage.setItem("db_jwt", t);
}
export function clearToken() {
  localStorage.removeItem("db_jwt");
}

// ── Base fetch helper ─────────────────────────────────────────────────────────
async function req<T>(
  method: string,
  path: string,
  body?: unknown,
  isFormData = false
): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body && !isFormData) headers["Content-Type"] = "application/json";

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: isFormData
      ? (body as FormData)
      : body
      ? JSON.stringify(body)
      : undefined,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data as T;
}

const get  = <T>(path: string)                => req<T>("GET",    path);
const post = <T>(path: string, body?: unknown) => req<T>("POST",   path, body);
const patch= <T>(path: string, body?: unknown) => req<T>("PATCH",  path, body);
const del  = <T>(path: string)                => req<T>("DELETE", path);

// ─────────────────────────────────────────────────────────────────────────────
//  AUTH
// ─────────────────────────────────────────────────────────────────────────────
export const auth = {
  patientSignup: (name: string, email: string, password: string) =>
    post<{ token: string; user: AppUser }>("/auth/patient/signup", { name, email, password }),

  patientLogin: (email: string, password: string) =>
    post<{ token: string; user: AppUser }>("/auth/patient/login", { email, password }),

  doctorLogin: (code: string, phone: string) =>
    post<{ token: string; user: AppUser }>("/auth/doctor/login", { code, phone }),

  adminLogin: (code: string, password: string) =>
    post<{ token: string; user: AppUser }>("/auth/admin/login", { code, password }),

  me: () => get<{ user: AppUser }>("/auth/me"),
};

// ─────────────────────────────────────────────────────────────────────────────
//  HOSPITALS
// ─────────────────────────────────────────────────────────────────────────────
export const hospitals = {
  list: ()                              => get<Hospital[]>("/hospitals"),
  get:  (id: string)                    => get<Hospital>(`/hospitals/${id}`),
  create: (data: Partial<Hospital>)     => post<Hospital>("/hospitals", data),
  update: (id: string, data: Partial<Hospital>) => patch<Hospital>(`/hospitals/${id}`, data),
  delete: (id: string)                  => del<{ success: boolean }>(`/hospitals/${id}`),
  uploadPhoto: (id: string, file: File) => {
    const fd = new FormData();
    fd.append("photo", file);
    return req<{ photoUrl: string }>("POST", `/hospitals/${id}/photo`, fd, true);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  DOCTORS
// ─────────────────────────────────────────────────────────────────────────────
export const doctors = {
  list: (hospitalId?: string) =>
    get<Doctor[]>(hospitalId ? `/doctors?hospitalId=${hospitalId}` : "/doctors"),
  get:    (id: string)                  => get<Doctor>(`/doctors/${id}`),
  create: (data: Partial<Doctor>)       => post<Doctor>("/doctors", data),
  update: (id: string, data: Partial<Doctor>) => patch<Doctor>(`/doctors/${id}`, data),
  delete: (id: string)                  => del<{ success: boolean }>(`/doctors/${id}`),
};

// ─────────────────────────────────────────────────────────────────────────────
//  BOOKINGS
// ─────────────────────────────────────────────────────────────────────────────
export const bookings = {
  list: ()                              => get<Booking[]>("/bookings"),
  forSession: (sessionId: string)       => get<Booking[]>(`/bookings/session/${sessionId}`),
  create: (data: {
    doctorId: string; date: string; session: string;
    complaint?: string; phone?: string;
  })                                    => post<Booking>("/bookings", data),
  updateStatus: (id: string, status: string) =>
    patch<Booking>(`/bookings/${id}/status`, { status }),
  stats: ()                             => get<Stats>("/bookings/stats/summary"),
};

// ─────────────────────────────────────────────────────────────────────────────
//  TOKEN STATES
// ─────────────────────────────────────────────────────────────────────────────
export const tokens = {
  getState: (sessionId: string)         => get<SessionTokenState | null>(`/tokens/${sessionId}`),
  regulate: (sessionId: string, clickedToken: number) =>
    post<SessionTokenState>(`/tokens/${sessionId}/regulate`, { clickedToken }),
  complete: (sessionId: string)         => post<SessionTokenState>(`/tokens/${sessionId}/complete`),
  skip:     (sessionId: string)         => post<SessionTokenState>(`/tokens/${sessionId}/skip`),
  completeSkipped: (sessionId: string, tokenNum: number) =>
    post<SessionTokenState>(`/tokens/${sessionId}/complete-skipped`, { tokenNum }),
  closeSession: (sessionId: string)     => post<SessionTokenState>(`/tokens/${sessionId}/close`),
  setPrioritySlot: (sessionId: string, slotIndex: number, slot: PrioritySlotState) =>
    post<SessionTokenState>(`/tokens/${sessionId}/priority-slot`, { slotIndex, slot }),
  cancelSession: (doctorId: string, date: string, session: string) =>
    post<{ success: boolean }>("/tokens/cancel-session", { doctorId, date, session }),
  getCancelledSessions: ()              => get<string[]>("/tokens/cancelled/list"),
};

// ─────────────────────────────────────────────────────────────────────────────
//  PATIENTS
// ─────────────────────────────────────────────────────────────────────────────
export const patients = {
  list: () => get<PatientRecord[]>("/patients"),
};

// ─────────────────────────────────────────────────────────────────────────────
//  WEBSOCKET — live token updates
// ─────────────────────────────────────────────────────────────────────────────
export function connectTokenSocket(
  sessionId: string,
  onMessage: (payload: { type: string; state?: SessionTokenState; tokenNumber?: number }) => void
): () => void {
  const url = `${WS_BASE}/ws?session=${encodeURIComponent(sessionId)}`;
  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let dead = false;

  function connect() {
    if (dead) return;
    ws = new WebSocket(url);
    ws.onmessage = (evt) => {
      try { onMessage(JSON.parse(evt.data)); } catch {}
    };
    ws.onclose = () => {
      if (!dead) reconnectTimer = setTimeout(connect, 3000);
    };
    ws.onerror = () => ws?.close();
  }

  connect();

  return () => {
    dead = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    ws?.close();
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Shared types (mirror of frontend types.ts)
// ─────────────────────────────────────────────────────────────────────────────
export type UserRole = "patient" | "doctor" | "admin";

export interface Hospital {
  id: string; name: string; area: string; address?: string;
  phone?: string; rating: number; gradient: string;
  photoUrl?: string | null; doctorCount: number;
}

export interface Doctor {
  id: string; hospitalId: string; code?: string; name: string;
  specialty: string; phone?: string; bio?: string; photo?: string | null;
  price: number; consultationFee?: number; tokensPerSession: number;
  sessions: string[]; sessionTimings?: Record<string, { start: string; end: string }> | null;
  isAvailable?: boolean; yearsOfExperience?: string; education?: string; languages?: string[];
}

export interface Booking {
  id: string; patientId: string; patientName: string;
  doctorId: string; doctorName: string; hospitalName: string;
  date: string; session: string; tokenNumber: number; sessionId: string;
  paymentDone: boolean; status: "confirmed" | "completed" | "unvisited" | "cancelled";
  phone?: string; complaint?: string; createdAt: string;
}

export type TokenStatus = "white" | "red" | "orange" | "yellow" | "green" | "unvisited";

export interface SessionTokenState {
  sessionId: string; doctorId: string; date: string; session: string;
  tokenStatuses: Record<number, TokenStatus>;
  prioritySlots: Record<number, PrioritySlotState>;
  currentToken: number | null; nextToken: number | null;
  isClosed: boolean; cancelledSessions: string[];
}

export interface PrioritySlotState {
  label: string; status: "waiting" | "ongoing" | "completed"; patientName?: string;
}

export interface PatientRecord {
  id: string; name: string; email?: string; createdAt: string;
}

export type AppUser =
  | { id: string; email: string; name: string; role: "patient" }
  | { id: string; code: string; doctorId: string; role: "doctor" }
  | { id: string; role: "admin" };

export interface Stats {
  totalHospitals: number; totalDoctors: number; totalPatients: number;
  totalBookings: number; activeSessions: number;
}
