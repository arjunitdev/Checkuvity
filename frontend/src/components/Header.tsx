import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Menu, X } from "lucide-react";

const navItems: { label: string; href: string }[] = [
  { label: "Home", href: "/" },
  { label: "About", href: "#about" },
  { label: "Projects", href: "/projects" },
  { label: "Chat", href: "#chat" },
  { label: "Contact", href: "#contact" },
];

const Header = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const location = useLocation();

  return (
    <header className="fixed top-0 left-0 right-0 z-50 header-red border-b border-border/50">
      <div className="max-w-6xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="text-xl font-bold tracking-tight" style={{ fontFamily: "var(--font-display)" }}>
            <span className="text-foreground">ARJUN SELVAM</span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-8">
            {navItems.map(({ label, href }) => {
              const isRoute = href.startsWith("/") && !href.startsWith("/#");
              const Comp = isRoute ? Link : "a";
              const compProps = isRoute ? { to: href } : { href };
              return (
                <Comp
                  key={label}
                  {...compProps}
                  className={`nav-link ${location.pathname === href ? "text-foreground" : ""}`}
                >
                  {label}
                </Comp>
              );
            })}
          </nav>

          {/* Mobile Menu Button */}
          <button
            className="md:hidden p-2 text-muted-foreground hover:text-foreground transition-colors"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-expanded={isMenuOpen}
            aria-label={isMenuOpen ? "Close menu" : "Open menu"}
          >
            {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Mobile Navigation */}
        {isMenuOpen && (
          <nav className="md:hidden mt-4 pb-4 border-t border-border/50 pt-4">
            <div className="flex flex-col gap-4">
              {navItems.map(({ label, href }) => {
                const isRoute = href.startsWith("/") && !href.startsWith("/#");
                const Comp = isRoute ? Link : "a";
                const compProps = isRoute ? { to: href } : { href };
                return (
                  <Comp
                    key={label}
                    {...compProps}
                    className="nav-link"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    {label}
                  </Comp>
                );
              })}
            </div>
          </nav>
        )}
      </div>
    </header>
  );
};

export default Header;
