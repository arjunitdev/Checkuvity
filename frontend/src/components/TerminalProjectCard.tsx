import { ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader } from "./ui/card";

interface TerminalProjectCardProps {
  title: string;
  description: string[];
  technologies: string[];
  youtubeUrl?: string;
  animationDelay?: string;
}

const TerminalProjectCard = ({
  title,
  description,
  technologies,
  youtubeUrl,
  animationDelay = "",
}: TerminalProjectCardProps) => {
  return (
    <Card
      className={`border-border bg-card text-card-foreground overflow-hidden transition-colors hover:border-border ${animationDelay}`}
    >
      <CardHeader className="border-b border-border/50 pb-4">
        <div className="flex items-start justify-between gap-4">
          <h3 className="text-lg font-semibold text-foreground" style={{ fontFamily: "var(--font-display)" }}>
            {title}
          </h3>
          {youtubeUrl && (
            <a
              href={youtubeUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="shrink-0 p-1.5 text-muted-foreground hover:text-terminal transition-colors rounded-md"
              aria-label="Watch demo"
            >
              <ExternalLink size={18} />
            </a>
          )}
        </div>
      </CardHeader>
      <CardContent className="pt-4 space-y-4">
        <ul className="space-y-2 text-sm text-muted-foreground">
          {description.map((line, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-terminal shrink-0">→</span>
              <span>{line}</span>
            </li>
          ))}
        </ul>
        <div className="flex flex-wrap gap-2 pt-2">
          {technologies.map((tech) => (
            <span
              key={tech}
              className="text-xs font-mono px-2 py-1 rounded-md bg-muted text-muted-foreground border border-border/50"
            >
              {tech}
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default TerminalProjectCard;
