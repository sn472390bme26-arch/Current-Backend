/**
 * LoginPage.tsx — updated to call the real backend API.
 * Drop this into src/frontend/src/pages/LoginPage.tsx
 */
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Activity,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  ShieldCheck,
  User,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { auth } from "../api";
import { useStore } from "../context/StoreContext";
import { useRouter } from "../router/RouterContext";

export default function LoginPage() {
  const { login, doctors } = useStore();
  const { navigate } = useRouter();

  const [patientMode, setPatientMode] = useState<"login" | "signup">("signup");
  const [patientEmail, setPatientEmail] = useState("");
  const [patientPassword, setPatientPassword] = useState("");
  const [patientName, setPatientName] = useState("");

  const [doctorCode, setDoctorCode] = useState("");
  const [doctorPassword, setDoctorPassword] = useState("");
  const [adminCode, setAdminCode] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [showAdminPassword, setShowAdminPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  function switchPatientMode(mode: "login" | "signup") {
    setPatientMode(mode);
    setPatientEmail("");
    setPatientPassword("");
    setPatientName("");
  }

  async function handlePatientSignup(e: React.FormEvent) {
    e.preventDefault();
    const name = patientName.trim();
    const email = patientEmail.trim().toLowerCase();
    const password = patientPassword;
    if (!name || !email || !password) {
      toast.error("Please fill all fields");
      return;
    }
    setLoading(true);
    try {
      const { token, user } = await auth.patientSignup(name, email, password);
      login(user, token);
      navigate({ path: "/patient/hospitals" });
    } catch (err: any) {
      toast.error(err.message || "Sign up failed");
    } finally {
      setLoading(false);
    }
  }

  async function handlePatientLogin(e: React.FormEvent) {
    e.preventDefault();
    const email = patientEmail.trim().toLowerCase();
    const password = patientPassword;
    if (!email || !password) {
      toast.error("Please fill all fields");
      return;
    }
    setLoading(true);
    try {
      const { token, user } = await auth.patientLogin(email, password);
      login(user, token);
      navigate({ path: "/patient/hospitals" });
    } catch (err: any) {
      toast.error(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleDoctorLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!doctorCode) { toast.error("Please enter your doctor code"); return; }
    if (!doctorPassword) { toast.error("Please enter your phone number as password"); return; }
    setLoading(true);
    try {
      const { token, user } = await auth.doctorLogin(doctorCode.trim(), doctorPassword.trim());
      login(user, token);
      navigate({ path: "/doctor" });
    } catch (err: any) {
      toast.error(err.message || "Doctor login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleAdminLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!adminCode || !adminPassword) {
      toast.error("Please enter admin code and password");
      return;
    }
    setLoading(true);
    try {
      const { token, user } = await auth.adminLogin(adminCode.trim(), adminPassword);
      login(user, token);
      navigate({ path: "/admin" });
    } catch (err: any) {
      toast.error(err.message || "Admin login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <header className="bg-white border-b border-gray-200 px-4 sm:px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center gap-2">
          <img
            src="/assets/uploads/final_logo_page-0001-019d2d83-8a36-752f-9b4e-dec5e9e187fd-1.jpg"
            alt="Doctor Booked Logo"
            className="w-8 h-8 rounded-full object-cover shrink-0"
          />
          <span className="text-base">
            <span className="font-bold text-gray-900">Doctor</span>
            <span className="font-bold text-teal-500"> Booked</span>
          </span>
        </div>
      </header>

      <div className="flex-1 flex items-center justify-center px-4 py-8 sm:py-12">
        <div className="w-full max-w-4xl">
          <Tabs defaultValue="patient" className="w-full">
            <TabsList className="grid w-full max-w-sm mx-auto grid-cols-3 mb-6 sm:mb-8">
              <TabsTrigger value="patient">Patient</TabsTrigger>
              <TabsTrigger value="doctor">Doctor</TabsTrigger>
              <TabsTrigger value="admin">Admin</TabsTrigger>
            </TabsList>

            {/* ── Patient tab ── */}
            <TabsContent value="patient">
              <div className="flex flex-col sm:flex-row max-w-3xl mx-auto rounded-2xl overflow-hidden shadow-sm border border-gray-100">
                <div className="hidden sm:flex sm:w-2/5 bg-gradient-to-b from-teal-200 to-teal-500 items-end pb-10 px-8 min-h-[280px]">
                  <div>
                    <h2 className="text-2xl font-bold text-white leading-tight mb-2">
                      Your Health,<br />Prioritized.
                    </h2>
                    <p className="text-teal-50 text-sm leading-relaxed">
                      Book appointments, track your token, and skip the waiting room stress.
                    </p>
                  </div>
                </div>
                <div className="flex-1 bg-white p-6 sm:p-8">
                  <div className="mb-5 hidden sm:block">
                    <div className="w-12 h-12 bg-teal-100 rounded-xl flex items-center justify-center mb-4">
                      <Activity className="w-6 h-6 text-teal-600" />
                    </div>
                    <h3 className="text-xl font-bold text-gray-900">Patient Portal</h3>
                    <p className="text-gray-500 text-sm mt-1">
                      {patientMode === "signup" ? "Create your account" : "Welcome back"}
                    </p>
                  </div>

                  {patientMode === "signup" ? (
                    <form onSubmit={handlePatientSignup} className="space-y-4">
                      <div className="space-y-1.5">
                        <Label htmlFor="patient-name">Full Name</Label>
                        <div className="relative">
                          <User className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                          <Input id="patient-name" className="pl-9" placeholder="Your full name"
                            value={patientName} onChange={e => setPatientName(e.target.value)} />
                        </div>
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="patient-email">Email</Label>
                        <div className="relative">
                          <Mail className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                          <Input id="patient-email" type="email" className="pl-9" placeholder="your@email.com"
                            value={patientEmail} onChange={e => setPatientEmail(e.target.value)} />
                        </div>
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="patient-password">Password</Label>
                        <div className="relative">
                          <Lock className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                          <Input id="patient-password" type="password" className="pl-9" placeholder="Create a password (min 6 chars)"
                            value={patientPassword} onChange={e => setPatientPassword(e.target.value)} />
                        </div>
                      </div>
                      <Button type="submit" className="w-full bg-teal-500 hover:bg-teal-600 rounded-full h-11" disabled={loading}>
                        {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Creating account...</> : "Sign Up"}
                      </Button>
                      <p className="text-xs text-center text-gray-500">
                        Already have an account?{" "}
                        <button type="button" className="text-teal-600 hover:underline font-medium"
                          onClick={() => switchPatientMode("login")}>Log in</button>
                      </p>
                    </form>
                  ) : (
                    <form onSubmit={handlePatientLogin} className="space-y-4">
                      <div className="space-y-1.5">
                        <Label htmlFor="patient-email-login">Email</Label>
                        <div className="relative">
                          <Mail className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                          <Input id="patient-email-login" type="email" className="pl-9" placeholder="your@email.com"
                            value={patientEmail} onChange={e => setPatientEmail(e.target.value)} />
                        </div>
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="patient-password-login">Password</Label>
                        <div className="relative">
                          <Lock className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                          <Input id="patient-password-login" type="password" className="pl-9" placeholder="Enter your password"
                            value={patientPassword} onChange={e => setPatientPassword(e.target.value)} />
                        </div>
                      </div>
                      <Button type="submit" className="w-full bg-teal-500 hover:bg-teal-600 rounded-full h-11" disabled={loading}>
                        {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Signing in...</> : "Login"}
                      </Button>
                      <p className="text-xs text-center text-gray-500">
                        Don't have an account?{" "}
                        <button type="button" className="text-teal-600 hover:underline font-medium"
                          onClick={() => switchPatientMode("signup")}>Sign up</button>
                      </p>
                    </form>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* ── Doctor tab ── */}
            <TabsContent value="doctor">
              <div className="max-w-sm mx-auto bg-white rounded-2xl shadow-sm border border-gray-100 p-6 sm:p-8">
                <div className="flex flex-col items-center mb-6">
                  <div className="w-16 h-16 rounded-full overflow-hidden mb-4">
                    <img src="/assets/uploads/final_logo_page-0001-019d2d83-8a36-752f-9b4e-dec5e9e187fd-1.jpg"
                      alt="Doctor Booked Logo" className="w-full h-full object-cover" />
                  </div>
                  <h3 className="text-xl font-bold text-gray-900">Doctor Login</h3>
                  <p className="text-gray-500 text-sm mt-1 text-center">Enter your assigned login credentials</p>
                </div>
                <form onSubmit={handleDoctorLogin} className="space-y-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="doctor-code">Doctor Login Code</Label>
                    <div className="relative">
                      <KeyRound className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                      <Input id="doctor-code" className="pl-9 font-mono tracking-widest" placeholder="DOC-00001"
                        value={doctorCode} onChange={e => setDoctorCode(e.target.value)} />
                    </div>
                    <p className="text-xs text-gray-400">Your unique code assigned by the admin</p>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="doctor-phone">Phone Number (Password)</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                      <Input id="doctor-phone" type="password" className="pl-9" placeholder="Enter your registered phone number"
                        value={doctorPassword} onChange={e => setDoctorPassword(e.target.value)} />
                    </div>
                    <p className="text-xs text-gray-400">Your password is the phone number registered by the admin</p>
                  </div>
                  <Button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 rounded-full h-11" disabled={loading}>
                    {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Verifying...</> : "Access Dashboard"}
                  </Button>
                </form>
              </div>
            </TabsContent>

            {/* ── Admin tab ── */}
            <TabsContent value="admin">
              <div className="max-w-sm mx-auto bg-white rounded-2xl shadow-sm border border-gray-100 p-6 sm:p-8">
                <div className="flex flex-col items-center mb-6">
                  <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mb-4">
                    <ShieldCheck className="w-8 h-8 text-slate-600" />
                  </div>
                  <h3 className="text-xl font-bold text-gray-900">Admin Portal</h3>
                  <p className="text-gray-500 text-sm mt-1 text-center">System administration &amp; management</p>
                </div>
                <form onSubmit={handleAdminLogin} className="space-y-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="admin-code">Admin Code</Label>
                    <div className="relative">
                      <ShieldCheck className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                      <Input id="admin-code" className="pl-9 font-mono tracking-widest" placeholder="ADMIN-001"
                        value={adminCode} onChange={e => setAdminCode(e.target.value)} />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="admin-password">Password</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                      <Input id="admin-password" type={showAdminPassword ? "text" : "password"}
                        className="pl-9 pr-9" placeholder="Enter admin password"
                        value={adminPassword} onChange={e => setAdminPassword(e.target.value)} />
                      <button type="button" className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600"
                        onClick={() => setShowAdminPassword(v => !v)} tabIndex={-1}>
                        {showAdminPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  <Button type="submit" className="w-full rounded-full h-11" disabled={loading}>
                    {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Verifying...</> : "Login as Admin"}
                  </Button>
                </form>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      <footer className="py-6 text-center text-xs text-gray-400 border-t border-gray-100">
        &copy; {new Date().getFullYear()}. Built with ❤️ using{" "}
        <a href={`https://caffeine.ai`} className="underline hover:text-gray-600"
          target="_blank" rel="noopener noreferrer">caffeine.ai</a>
      </footer>
    </div>
  );
}
