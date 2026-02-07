import { ExternalLink } from "lucide-react";

interface ProjectCardProps {
  title: string;
  description: string;
  technologies: string[];
  imageUrl: string;
  projectUrl?: string;
  date?: string;
  institution?: string;
  animationDelay?: string;
}

const ProjectCard = ({
  title,
  description,
  technologies,
  imageUrl,
  projectUrl = "#",
  date,
  institution,
  animationDelay = "",
}: ProjectCardProps) => {
  return (
    <div
      className={`group card-glass rounded-xl overflow-hidden transition-all duration-500 hover:scale-[1.02] animate-fade-up ${animationDelay}`}
    >
      {/* Image Container */}
      <div className="relative h-48 overflow-hidden">
        <img
          src={imageUrl}
          alt={title}
          className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
        />
        <div className="absolute inset-0 bg-gradient-to-t from-card via-transparent to-transparent opacity-60" />

        {/* Date Badge */}
        {date && (
          <div className="absolute top-4 left-4 px-3 py-1 rounded-full bg-background/80 backdrop-blur-sm text-xs font-medium text-muted-foreground">
            {date}
          </div>
        )}
      </div>

      {/* Content */}
      <div className="p-6 space-y-4">
        <div>
          <h3
            className="text-lg font-semibold text-foreground group-hover:text-gradient transition-all duration-300"
            style={{ fontFamily: "var(--font-display)" }}
          >
            {title}
          </h3>
          {institution && (
            <p className="text-sm text-muted-foreground mt-1">{institution}</p>
          )}
        </div>

        <p className="text-sm text-muted-foreground leading-relaxed line-clamp-3">
          {description}
        </p>

        {/* Technologies */}
        <div className="flex flex-wrap gap-2">
          {technologies.map((tech) => (
            <span key={tech} className="tech-badge">
              {tech}
            </span>
          ))}
        </div>

        {/* View Project Button */}
        <a
          href={projectUrl}
          target={projectUrl.startsWith("http") ? "_blank" : undefined}
          rel={projectUrl.startsWith("http") ? "noopener noreferrer" : undefined}
          className="inline-flex items-center gap-2 w-full justify-center py-3 rounded-lg btn-primary text-sm"
        >
          <ExternalLink size={16} />
          View Project
        </a>
      </div>
    </div>
  );
};

export default ProjectCard;
