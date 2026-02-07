import { Github, Linkedin, Terminal } from "lucide-react";

const Footer = () => {
  const quickLinks = ["Home", "About", "Projects", "Chat", "Contact"];

  return (
    <footer className="border-t border-border/50 bg-card/50 backdrop-blur-sm">
      <div className="max-w-6xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* Brand */}
          <div className="space-y-4">
            <h3 className="text-xl font-bold" style={{ fontFamily: "var(--font-display)" }}>
              <span className="text-terminal cursor-blink">ARJUN SELVAM</span>
            </h3>
            <p className="text-sm text-muted-foreground max-w-sm font-mono">
              <Terminal size={14} className="inline text-terminal mr-2" />
              Data Scientist & Developer specializing in AI, ML, and Cloud Systems.
            </p>
          </div>

          {/* Quick Links */}
          <div className="space-y-4">
            <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground font-mono">
              <span className="text-terminal">$</span> Quick Links
            </h4>
            <nav className="flex flex-col gap-2">
              {quickLinks.map((link) => (
                <a
                  key={link}
                  href={`#${link.toLowerCase()}`}
                  className="text-sm text-muted-foreground hover:text-terminal transition-colors font-mono"
                >
                  → {link}
                </a>
              ))}
            </nav>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-12 pt-8 border-t border-border/50 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground font-mono">
            © 2025 Arjun Selvam. All rights reserved.
          </p>
          <div className="flex items-center gap-4">
            <a
              href="#"
              className="p-2 text-muted-foreground hover:text-terminal transition-colors"
              aria-label="LinkedIn"
            >
              <Linkedin size={20} />
            </a>
            <a
              href="#"
              className="p-2 text-muted-foreground hover:text-terminal transition-colors"
              aria-label="GitHub"
            >
              <Github size={20} />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
