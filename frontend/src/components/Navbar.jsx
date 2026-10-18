export default function Navbar({ onNavigate }) {
  return (
    <header className="w-full bg-white border-b border-border sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-8">
          <button
            type="button"
            onClick={() => onNavigate?.("dashboard")}
            className="flex items-center gap-2.5 focus:outline-none"
          >
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round" strokeWidth="2"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <span className="font-bold text-lg text-slate-900 tracking-tight">IPv6 Auditor</span>
          </button>

          {/* Nav links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium">
            <button
              type="button"
              onClick={() => onNavigate?.("dashboard")}
              className="text-blue-600 font-semibold relative py-1 border-b-2 border-blue-600 focus:outline-none"
            >
              Home
            </button>
            <a
              href="#about"
              className="text-slate-600 hover:text-slate-900 transition-colors"
            >
              About
            </a>
            <a
              href="#documentation"
              className="text-slate-600 hover:text-slate-900 transition-colors"
            >
              Documentation
            </a>
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="text-slate-600 hover:text-slate-900 transition-colors"
            >
              API
            </a>
            <a
              href="http://127.0.0.1:8000/api/health"
              target="_blank"
              rel="noreferrer"
              className="text-slate-600 hover:text-slate-900 transition-colors"
            >
              Status
            </a>
          </nav>
        </div>

        {/* Right side controls */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            className="p-2 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors focus:outline-none"
            title="Toggle Theme"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
              />
            </svg>
          </button>

          <div
            className="w-8 h-8 rounded-full bg-indigo-600 text-white font-semibold text-sm flex items-center justify-center shadow-xs cursor-pointer select-none"
            title="User Profile"
          >
            S
          </div>
        </div>
      </div>
    </header>
  );
}
