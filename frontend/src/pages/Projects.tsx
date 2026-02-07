import Header from "@/components/Header";
import TerminalProjectCard from "@/components/TerminalProjectCard";
import Footer from "@/components/Footer";

const projects = [
  {
    title: "CheckUvity: AI-Agent Security Verification",
    description: [
      "Architected a multi-agent AI pipeline using AutoGen to analyze cryptographic validation (RSA/SHA-256), threat intelligence analysis, and complex risk scoring.",
      "Developed a real-time risk scoring engine that aggregated 10+ security data points (e.g., signature validity, file diffs) into a dynamic 0-100 score, quantifying threats with 99.9% accuracy.",
      "Deployed an autonomous Email Notifier agent that parsed AI-generated security assessments and automatically dispatched high-priority SMTP alerts on integrity violations, reducing manual review time by 98%.",
    ],
    technologies: ["AutoGen", "Python", "RSA/SHA-256", "SMTP", "AI Agents"],
    youtubeUrl: "https://www.youtube.com/watch?v=t_fUJcdVEUk",
  },
  {
    title: "Sentinel: Multi-Agent Incident Response",
    description: [
      "Built using Python/FastAPI and Google Gemini Pro, reduces root cause analysis time from hours to seconds.",
      "Deploys isolated AI specialist agents (DBA, Network, Code Auditor) with temporal forensics and a Judge synthesis layer.",
      "Eliminates alert fatigue, manual log correlation and log monitoring in distributed systems.",
    ],
    technologies: ["Python", "FastAPI", "Gemini Pro", "Multi-Agent", "Forensics"],
    youtubeUrl: "https://www.youtube.com/watch?v=4VkltiEfwuQ",
  },
  {
    title: "AI-Powered Music Mood Recommender",
    description: [
      "An AI system that recommends music based on user's emotional state detected through text.",
      "Uses sentiment analysis and music feature matching for personalized recommendations.",
    ],
    technologies: ["Python", "TensorFlow", "OpenCV"],
  },
  {
    title: "LinkUpPro: AI Job Application Helper",
    description: [
      "A tool that uses AI to match job descriptions with resumes and suggests improvements to increase match rate.",
      "Helps job seekers optimize their applications with intelligent recommendations.",
    ],
    technologies: ["Python", "NLP", "Flask"],
  },
  {
    title: "Real-Time Sales Dashboard",
    description: [
      "A real-time analytics dashboard for retail sales with predictive inventory management capabilities.",
      "Provides actionable insights for business decisions through interactive visualizations.",
    ],
    technologies: ["Tableau", "SQL", "Analytics"],
  },
  {
    title: "Automated Coffee Sales Analytics",
    description: [
      "An automated system for coffee shops to track sales, predict demand, and optimize inventory.",
      "Uses machine learning for accurate demand forecasting.",
    ],
    technologies: ["Excel", "Python", "ML"],
  },
  {
    title: "Quality Control Vision System",
    description: [
      "Created a system that inspects the quality of manufactured products using a high-resolution camera and OpenCV.",
      "Improved the speed and accuracy of product inspections through automation, without requiring conveyor movement.",
    ],
    technologies: ["OpenCV", "Computer Vision", "Python"],
  },
  {
    title: "Voice-Activated Timesheet Automation",
    description: [
      "A Python application that automates timesheet entry using speech recognition and AI.",
      "Integrates OpenAI Whisper for offline speech-to-text and GPT-4 for data extraction, achieving 90% reduction in logging time.",
    ],
    technologies: ["Python", "Whisper", "GPT-4", "Pandas"],
  },
];

const Projects = () => {
  return (
    <div className="min-h-screen bg-background">
      <Header />

      {/* Hero Section */}
      <section className="pt-32 pb-16 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="font-mono text-sm text-terminal mb-4 animate-fade-up">
            <span className="opacity-60">$</span> ./build --projects
          </div>
          <h1 className="text-4xl md:text-6xl font-bold mb-6 animate-fade-up animation-delay-100" style={{ fontFamily: "var(--font-display)" }}>
            <span className="text-terminal">PROJECTS</span>
          </h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto animate-fade-up animation-delay-200 font-mono">
            <span className="text-terminal">&gt;</span> A collection of systems I've built — from autonomous AI agents to real-time analytics platforms.
          </p>
          <div className="mt-4 font-mono text-xs text-muted-foreground animate-fade-up animation-delay-300">
            <span className="text-terminal">status:</span> always shipping <span className="cursor-blink text-terminal">▌</span>
          </div>
        </div>
      </section>

      {/* Projects Grid */}
      <section className="pb-24 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {projects.map((project, index) => (
              <TerminalProjectCard
                key={project.title}
                {...project}
                animationDelay={`animation-delay-${Math.min((index + 1) * 100, 800)}`}
              />
            ))}
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
};

export default Projects;
