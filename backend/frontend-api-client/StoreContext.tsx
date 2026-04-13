/**
 * StoreContext.tsx — wires the entire app to the real backend API.
 *
 * Drop this file into src/frontend/src/context/StoreContext.tsx
 * replacing the existing file.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import * as api from "../api";
import type {
  AppUser,
  Booking,
  Doctor,
  Hospital,
  PatientRecord,
  PrioritySlotState,
  SessionTokenState,
} from "../api";

// ── Re-export types so existing imports keep working ─────────────────────────
export type { AppUser, Booking, Doctor, Hospital, PatientRecord, SessionTokenState };

interface Store {
  // auth
  user: AppUser | null;
  login: (u: AppUser, token: string) => void;
  logout: () => void;
  // hospitals
  hospitals: Hospital[];
  loadHospitals: () => Promise<void>;
  addHospital: (data: Partial<Hospital>) => Promise<Hospital>;
  updateHospital: (id: string, data: Partial<Hospital>) => Promise<void>;
  updateHospitalPhoto: (id: string, file: File) => Promise<void>;
  deleteHospital: (id: string, _doctors: Doctor[]) => Promise<boolean>;
  // doctors
  doctors: Doctor[];
  loadDoctors: () => Promise<void>;
  addDoctor: (data: Omit<Doctor, "id" | "code">) => Promise<Doctor>;
  updateDoctor: (id: string, data: Partial<Doctor>) => Promise<void>;
  deleteDoctor: (id: string) => Promise<void>;
  // bookings
  bookings: Booking[];
  loadBookings: () => Promise<void>;
  addBooking: (data: { doctorId: string; date: string; session: string; complaint?: string; phone?: string }) => Promise<Booking>;
  getBookingsForPatient: (patientId: string) => Booking[];
  getBookingsForSession: (sessionId: string) => Booking[];
  // patients
  patients: PatientRecord[];
  loadPatients: () => Promise<void>;
  // token states
  tokenStates: Record<string, SessionTokenState>;
  loadTokenState: (sessionId: string) => Promise<void>;
  getOrCreateTokenState: (sessionId: string, doctorId: string, date: string, session: string) => SessionTokenState;
  bookToken: (sessionId: string, doctorId: string, date: string, session: string, tokenNumber: number) => void;
  regulateToken: (sessionId: string, clickedToken: number) => Promise<void>;
  completeCurrentToken: (sessionId: string) => Promise<void>;
  skipToken: (sessionId: string) => Promise<void>;
  completeSkippedToken: (sessionId: string, tokenNum: number) => Promise<void>;
  closeSession: (sessionId: string) => Promise<void>;
  setPrioritySlot: (sessionId: string, slotIndex: number, slot: PrioritySlotState) => Promise<void>;
  cancelSession: (doctorId: string, date: string, session: string) => Promise<void>;
  isSessionCancelled: (doctorId: string, date: string, session: string) => boolean;
  cancelledSessions: string[];
  // stats
  getStats: () => { totalHospitals: number; totalDoctors: number; totalPatients: number; totalBookings: number; activeSessions: number };
  // misc
  notification: string | null;
  setNotification: (n: string | null) => void;
  refreshFromStorage: () => Promise<void>;
}

const StoreCtx = createContext<Store | null>(null);

export function useStore(): Store {
  const ctx = useContext(StoreCtx);
  if (!ctx) throw new Error("useStore must be inside StoreProvider");
  return ctx;
}

export function StoreProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AppUser | null>(() => {
    try { return JSON.parse(localStorage.getItem("db_user") || "null"); } catch { return null; }
  });
  const [hospitals, setHospitals] = useState<Hospital[]>([]);
  const [doctors, setDoctors] = useState<Doctor[]>([]);
  const [bookings, setBookings] = useState<Booking[]>([]);
  const [patients, setPatients] = useState<PatientRecord[]>([]);
  const [tokenStates, setTokenStates] = useState<Record<string, SessionTokenState>>({});
  const [cancelledSessions, setCancelledSessions] = useState<string[]>([]);
  const [notification, setNotification] = useState<string | null>(null);
  const wsCleanups = useRef<Record<string, () => void>>({});

  // ── Auth ──────────────────────────────────────────────────────────────────
  const login = useCallback((u: AppUser, token: string) => {
    api.setToken(token);
    localStorage.setItem("db_user", JSON.stringify(u));
    setUser(u);
  }, []);

  const logout = useCallback(() => {
    api.clearToken();
    localStorage.removeItem("db_user");
    setUser(null);
    setBookings([]);
    setTokenStates({});
  }, []);

  // ── Data loaders ──────────────────────────────────────────────────────────
  const loadHospitals = useCallback(async () => {
    const data = await api.hospitals.list();
    setHospitals(data);
  }, []);

  const loadDoctors = useCallback(async () => {
    const data = await api.doctors.list();
    setDoctors(data);
  }, []);

  const loadBookings = useCallback(async () => {
    if (!user) return;
    const data = await api.bookings.list();
    setBookings(data);
  }, [user]);

  const loadPatients = useCallback(async () => {
    if (user?.role !== "admin") return;
    const data = await api.patients.list();
    setPatients(data);
  }, [user]);

  const loadTokenState = useCallback(async (sessionId: string) => {
    const state = await api.tokens.getState(sessionId);
    if (state) setTokenStates(prev => ({ ...prev, [sessionId]: state }));
  }, []);

  const refreshFromStorage = useCallback(async () => {
    // Re-fetch token states for any sessions we're watching
    for (const sessionId of Object.keys(tokenStates)) {
      await loadTokenState(sessionId);
    }
  }, [tokenStates, loadTokenState]);

  // Initial load
  useEffect(() => {
    loadHospitals();
    loadDoctors();
    api.tokens.getCancelledSessions().then(setCancelledSessions).catch(() => {});
    if (user) loadBookings();
    if (user?.role === "admin") loadPatients();
  }, [user]);  // eslint-disable-line

  // Subscribe WebSocket for any sessionId we're actively watching
  const subscribeSession = useCallback((sessionId: string) => {
    if (wsCleanups.current[sessionId]) return;
    const cleanup = api.connectTokenSocket(sessionId, (payload) => {
      if (payload.type === "state_update" && payload.state) {
        setTokenStates(prev => ({ ...prev, [sessionId]: payload.state! }));
      } else if (payload.type === "token_booked") {
        loadTokenState(sessionId);
      }
    });
    wsCleanups.current[sessionId] = cleanup;
  }, [loadTokenState]);

  // ── Hospitals ─────────────────────────────────────────────────────────────
  const addHospital = useCallback(async (data: Partial<Hospital>) => {
    const h = await api.hospitals.create(data);
    setHospitals(prev => [...prev, h]);
    return h;
  }, []);

  const updateHospital = useCallback(async (id: string, data: Partial<Hospital>) => {
    const h = await api.hospitals.update(id, data);
    setHospitals(prev => prev.map(x => x.id === id ? h : x));
  }, []);

  const updateHospitalPhoto = useCallback(async (id: string, file: File) => {
    const { photoUrl } = await api.hospitals.uploadPhoto(id, file);
    setHospitals(prev => prev.map(x => x.id === id ? { ...x, photoUrl } : x));
  }, []);

  const deleteHospital = useCallback(async (id: string, _docs: Doctor[]) => {
    try {
      await api.hospitals.delete(id);
      setHospitals(prev => prev.filter(h => h.id !== id));
      return true;
    } catch (e: any) {
      if (e.message?.includes("assigned doctors")) return false;
      throw e;
    }
  }, []);

  // ── Doctors ───────────────────────────────────────────────────────────────
  const addDoctor = useCallback(async (data: Omit<Doctor, "id" | "code">) => {
    const d = await api.doctors.create(data as Partial<Doctor>);
    setDoctors(prev => [...prev, d]);
    return d;
  }, []);

  const updateDoctor = useCallback(async (id: string, data: Partial<Doctor>) => {
    const d = await api.doctors.update(id, data);
    setDoctors(prev => prev.map(x => x.id === id ? d : x));
  }, []);

  const deleteDoctor = useCallback(async (id: string) => {
    await api.doctors.delete(id);
    setDoctors(prev => prev.filter(d => d.id !== id));
    setBookings(prev => prev.map(b => b.doctorId === id ? { ...b, status: "cancelled" as const } : b));
  }, []);

  // ── Bookings ──────────────────────────────────────────────────────────────
  const addBooking = useCallback(async (data: { doctorId: string; date: string; session: string; complaint?: string; phone?: string }) => {
    const b = await api.bookings.create(data);
    setBookings(prev => [...prev, b]);
    // Subscribe to live updates for this session
    subscribeSession(b.sessionId);
    return b;
  }, [subscribeSession]);

  const getBookingsForPatient = useCallback((patientId: string) =>
    bookings.filter(b => b.patientId === patientId), [bookings]);

  const getBookingsForSession = useCallback((sessionId: string) =>
    bookings.filter(b => b.sessionId === sessionId), [bookings]);

  // ── Token states ──────────────────────────────────────────────────────────
  const EMPTY_STATE = (sessionId: string, doctorId: string, date: string, session: string): SessionTokenState => ({
    sessionId, doctorId, date, session,
    tokenStatuses: {}, prioritySlots: {}, currentToken: null, nextToken: null,
    isClosed: false, cancelledSessions: [],
  });

  const getOrCreateTokenState = useCallback((sessionId: string, doctorId: string, date: string, session: string): SessionTokenState => {
    if (!tokenStates[sessionId]) {
      // Kick off a background load + subscribe
      loadTokenState(sessionId);
      subscribeSession(sessionId);
      return EMPTY_STATE(sessionId, doctorId, date, session);
    }
    subscribeSession(sessionId);
    return tokenStates[sessionId];
  }, [tokenStates, loadTokenState, subscribeSession]);

  const bookToken = useCallback((_sessionId: string, _doctorId: string, _date: string, _session: string, _tokenNumber: number) => {
    // Handled server-side during booking creation; local state updated via WS
  }, []);

  const regulateToken = useCallback(async (sessionId: string, clickedToken: number) => {
    const state = await api.tokens.regulate(sessionId, clickedToken);
    setTokenStates(prev => ({ ...prev, [sessionId]: state }));
  }, []);

  const completeCurrentToken = useCallback(async (sessionId: string) => {
    const state = await api.tokens.complete(sessionId);
    setTokenStates(prev => ({ ...prev, [sessionId]: state }));
  }, []);

  const skipToken = useCallback(async (sessionId: string) => {
    const state = await api.tokens.skip(sessionId);
    setTokenStates(prev => ({ ...prev, [sessionId]: state }));
  }, []);

  const completeSkippedToken = useCallback(async (sessionId: string, tokenNum: number) => {
    const state = await api.tokens.completeSkipped(sessionId, tokenNum);
    setTokenStates(prev => ({ ...prev, [sessionId]: state }));
  }, []);

  const closeSession = useCallback(async (sessionId: string) => {
    const state = await api.tokens.closeSession(sessionId);
    setTokenStates(prev => ({ ...prev, [sessionId]: state }));
    setBookings(prev => prev.map(b =>
      b.sessionId === sessionId && b.status === "confirmed" ? { ...b, status: "unvisited" as const } : b
    ));
  }, []);

  const setPrioritySlot = useCallback(async (sessionId: string, slotIndex: number, slot: PrioritySlotState) => {
    const state = await api.tokens.setPrioritySlot(sessionId, slotIndex, slot);
    setTokenStates(prev => ({ ...prev, [sessionId]: state }));
  }, []);

  const cancelSession = useCallback(async (doctorId: string, date: string, session: string) => {
    await api.tokens.cancelSession(doctorId, date, session);
    const key = `${doctorId}_${date}_${session}`;
    setCancelledSessions(prev => prev.includes(key) ? prev : [...prev, key]);
  }, []);

  const isSessionCancelled = useCallback((doctorId: string, date: string, session: string) =>
    cancelledSessions.includes(`${doctorId}_${date}_${session}`), [cancelledSessions]);

  // ── Stats ─────────────────────────────────────────────────────────────────
  const getStats = useCallback(() => ({
    totalHospitals: hospitals.length,
    totalDoctors: doctors.length,
    totalPatients: patients.length,
    totalBookings: bookings.length,
    activeSessions: Object.values(tokenStates).filter(s => !s.isClosed && s.currentToken !== null).length,
  }), [hospitals, doctors, patients, bookings, tokenStates]);

  const value: Store = {
    user, login, logout,
    hospitals, loadHospitals, addHospital, updateHospital, updateHospitalPhoto, deleteHospital,
    doctors, loadDoctors, addDoctor, updateDoctor, deleteDoctor,
    bookings, loadBookings, addBooking, getBookingsForPatient, getBookingsForSession,
    patients, loadPatients,
    tokenStates, loadTokenState, getOrCreateTokenState, bookToken,
    regulateToken, completeCurrentToken, skipToken, completeSkippedToken,
    closeSession, setPrioritySlot, cancelSession, isSessionCancelled, cancelledSessions,
    getStats,
    notification, setNotification,
    refreshFromStorage,
  };

  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}
