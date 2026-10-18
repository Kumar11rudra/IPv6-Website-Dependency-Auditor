import { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard";
import TermsOfUse from "./pages/TermsOfUse";
import PrivacyPolicy from "./pages/PrivacyPolicy";
import Footer from "./components/Footer";

export default function App() {
  const [view, setView] = useState(() => {
    if (typeof window !== "undefined") {
      const path = (window.location.pathname || "").toLowerCase();
      const hash = (window.location.hash || "").toLowerCase();
      if (hash === "#terms" || path === "/terms") return "terms";
      if (hash === "#privacy" || path === "/privacy") return "privacy";
    }
    return "dashboard";
  });

  useEffect(() => {
    const handleRoute = () => {
      const path = (window.location.pathname || "").toLowerCase();
      const hash = (window.location.hash || "").toLowerCase();
      if (hash === "#terms" || path === "/terms") setView("terms");
      else if (hash === "#privacy" || path === "/privacy") setView("privacy");
      else setView("dashboard");
    };
    window.addEventListener("hashchange", handleRoute);
    window.addEventListener("popstate", handleRoute);
    return () => {
      window.removeEventListener("hashchange", handleRoute);
      window.removeEventListener("popstate", handleRoute);
    };
  }, []);

  const navigate = (newView) => {
    if (newView === "terms") {
      window.location.hash = "#terms";
      setView("terms");
    } else if (newView === "privacy") {
      window.location.hash = "#privacy";
      setView("privacy");
    } else {
      window.location.hash = "";
      setView("dashboard");
    }
  };

  if (view === "terms") {
    return (
      <div className="min-h-screen flex flex-col justify-between w-full bg-bg">
        <main className="flex-1 w-full">
          <TermsOfUse onBack={() => navigate("dashboard")} onNavigate={navigate} />
        </main>
        <Footer onNavigate={navigate} />
      </div>
    );
  }

  if (view === "privacy") {
    return (
      <div className="min-h-screen flex flex-col justify-between w-full bg-bg">
        <main className="flex-1 w-full">
          <PrivacyPolicy onBack={() => navigate("dashboard")} onNavigate={navigate} />
        </main>
        <Footer onNavigate={navigate} />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col flex-1 bg-bg">
      <Dashboard onNavigate={navigate} />
    </div>
  );
}
