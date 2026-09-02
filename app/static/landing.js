/**
 * Valorynn Landing Page - JavaScript
 * Handles animations, theme toggling, and interactivity
 */

// ===========================
// Theme Management
// ===========================
class ThemeManager {
  constructor() {
    this.theme = localStorage.getItem('valorynn-theme') || 'dark';
    this.initialize();
  }

  initialize() {
    this.applyTheme(this.theme);
    this.attachThemeToggle();
  }

  attachThemeToggle() {
    const toggle = document.querySelector('.theme-toggle');
    if (toggle) {
      toggle.addEventListener('click', () => this.toggleTheme());
    }
  }

  toggleTheme() {
    this.theme = this.theme === 'dark' ? 'light' : 'dark';
    this.applyTheme(this.theme);
    localStorage.setItem('valorynn-theme', this.theme);
  }

  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.setAttribute('data-theme', theme);
  }
}

// ===========================
// Scroll Animations
// ===========================
class ScrollAnimations {
  constructor() {
    this.observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -100px 0px'
    };
    this.initialize();
  }

  initialize() {
    this.observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('scroll-fade-in');
          this.observer.unobserve(entry.target);
        }
      });
    }, this.observerOptions);

    document.querySelectorAll('.section, .feature-card, .step-card, .audience-card, .surface-node').forEach((element, index) => {
      element.style.setProperty('--reveal-delay', `${(index % 6) * 80}ms`);
      this.observer.observe(element);
    });
  }
}

// ===========================
// FAQ Accordion
// ===========================
class FAQAccordion {
  constructor() {
    this.initialize();
  }

  initialize() {
    const faqItems = document.querySelectorAll('.faq-item');
    
    faqItems.forEach(item => {
      const question = item.querySelector('.faq-question');
      const answer = item.querySelector('.faq-answer');
      
      question.addEventListener('click', () => {
        this.toggleItem(item, question, answer);
      });
    });
  }

  toggleItem(item, question, answer) {
    // Close other items
    document.querySelectorAll('.faq-item').forEach(otherItem => {
      if (otherItem !== item) {
        const otherQuestion = otherItem.querySelector('.faq-question');
        const otherAnswer = otherItem.querySelector('.faq-answer');
        otherQuestion.classList.remove('active');
        otherAnswer.classList.remove('active');
      }
    });

    // Toggle current item
    question.classList.toggle('active');
    answer.classList.toggle('active');
  }
}

// ===========================
// Hero Workflow Animation
// ===========================
class WorkflowAnimation {
  constructor() {
    this.currentStep = 0;
    this.steps = ['application', 'scan', 'analyze', 'findings', 'risk', 'fix', 'verify'];
    this.animateWorkflow();
  }

  animateWorkflow() {
    this.highlightStep();
    setInterval(() => {
      this.highlightStep();
      this.currentStep = (this.currentStep + 1) % this.steps.length;
    }, 2000);
  }

  highlightStep() {
    const allSteps = document.querySelectorAll('.workflow-step');
    allSteps.forEach(step => {
      step.style.opacity = '0.5';
      step.style.transform = 'scale(0.95)';
    });

    const currentStepElement = document.querySelector(`[data-step="${this.steps[this.currentStep]}"]`);
    if (currentStepElement) {
      currentStepElement.style.opacity = '1';
      currentStepElement.style.transform = 'scale(1.1)';
    }
  }
}

// ===========================
// Security Score Animation
// ===========================
class ScoreAnimation {
  constructor() {
    this.initialize();
  }

  initialize() {
    const scoreElement = document.querySelector('.score-value');
    const scoreRing = document.querySelector('.score-ring');
    
    if (scoreElement && scoreRing) {
      // Trigger animation when element enters viewport
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            this.animateScore(scoreElement, scoreRing);
            observer.unobserve(entry.target);
          }
        });
      }, { threshold: 0.5 });

      observer.observe(scoreElement.closest('.score-visualization'));
    }
  }

  animateScore(scoreElement, scoreRing) {
    scoreRing.classList.add('is-animated');
    const targetScore = parseInt(scoreElement.dataset.score);
    let currentScore = 0;
    const duration = 2000;
    const increment = targetScore / (duration / 16);
    const startTime = Date.now();

    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      currentScore = Math.floor(targetScore * progress);

      scoreElement.textContent = currentScore;

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    animate();
  }
}

// ===========================
// FixSignal Simulator
// ===========================
class FixSignalSimulator {
  constructor() {
    this.currentScore = 72;
    this.maxScore = 91;
    this.initialize();
  }

  initialize() {
    const checkboxes = document.querySelectorAll('.fixsignal-demo input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
      checkbox.addEventListener('change', () => this.updateProjectedScore());
    });
  }

  updateProjectedScore() {
    const checkboxes = document.querySelectorAll('.fixsignal-demo input[type="checkbox"]:checked');
    const fixCount = checkboxes.length;
    
    // Simple calculation: each fix adds ~6-7 points
    const projectedScore = Math.min(this.currentScore + (fixCount * 6), this.maxScore);
    
    const projectedElement = document.querySelector('.fixsignal-score.projected');
    if (projectedElement) {
      projectedElement.textContent = `${this.currentScore} → ${Math.round(projectedScore)}`;
    }
  }
}

// ===========================
// Smooth Scroll for Navigation
// ===========================
class SmoothScroll {
  constructor() {
    this.initialize();
  }

  initialize() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', (e) => {
        e.preventDefault();
        const target = document.querySelector(anchor.getAttribute('href'));
        if (target) {
          target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
          });
        }
      });
    });
  }
}

// ===========================
// Morphing Button Animation
// ===========================
class MorphingButton {
  constructor() {
    this.initialize();
  }

  initialize() {
    const morphButtons = document.querySelectorAll('.morph-transition');
    morphButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        this.createMorphEffect(e);
      });
    });
  }

  createMorphEffect(e) {
    const button = e.currentTarget;
    const rect = button.getBoundingClientRect();
    const ripple = document.createElement('span');
    
    ripple.style.position = 'absolute';
    ripple.style.left = (e.clientX - rect.left) + 'px';
    ripple.style.top = (e.clientY - rect.top) + 'px';
    ripple.style.width = '20px';
    ripple.style.height = '20px';
    ripple.style.background = 'rgba(255, 255, 255, 0.5)';
    ripple.style.borderRadius = '50%';
    ripple.style.pointerEvents = 'none';
    ripple.style.animation = 'ripple 0.6s ease-out';
    
    button.appendChild(ripple);
    
    setTimeout(() => ripple.remove(), 600);
  }
}

// ===========================
// Navigation Active State
// ===========================
class NavigationActive {
  constructor() {
    this.initialize();
  }

  initialize() {
    window.addEventListener('scroll', () => this.updateActiveNav());
  }

  updateActiveNav() {
    const sections = document.querySelectorAll('.section');
    let currentSection = '';

    sections.forEach(section => {
      const sectionTop = section.offsetTop;
      if (window.pageYOffset >= sectionTop - 200) {
        currentSection = section.getAttribute('id');
      }
    });

    document.querySelectorAll('.nav-link').forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${currentSection}`) {
        link.classList.add('active');
      }
    });
  }
}

// ===========================
// Logo Animation
// ===========================
class LogoAnimation {
  constructor() {
    this.initialize();
  }

  initialize() {
    const logoElements = document.querySelectorAll('.logo-element');
    if (logoElements.length > 0) {
      this.animateLogoElements(logoElements);
    }
  }

  animateLogoElements(elements) {
    elements.forEach((element, index) => {
      element.style.animation = `logoElementAnimation ${0.8}s ease-out ${index * 0.1}s both`;
    });
  }
}

// ===========================
// Ripple Effect Animation CSS
// ===========================
function injectRippleAnimation() {
  const style = document.createElement('style');
  style.textContent = `
    @keyframes ripple {
      0% {
        width: 20px;
        height: 20px;
        opacity: 1;
        transform: scale(0);
      }
      100% {
        width: 20px;
        height: 20px;
        opacity: 0;
        transform: scale(4);
      }
    }

    @keyframes logoElementAnimation {
      0% {
        opacity: 0;
        transform: scale(0) rotate(-180deg);
      }
      100% {
        opacity: 1;
        transform: scale(1) rotate(0deg);
      }
    }
  `;
  document.head.appendChild(style);
}

// ===========================
// Parallax Scroll Effect
// ===========================
class ParallaxEffect {
  constructor() {
    this.initialize();
  }

  initialize() {
    const heroSection = document.querySelector('.hero');
    if (heroSection) {
      heroSection.style.transform = '';
    }
  }
}

// ===========================
// Initialize All Components
// ===========================
document.addEventListener('DOMContentLoaded', () => {
  // Inject animations
  injectRippleAnimation();

  // Initialize components
  new ThemeManager();
  new ScrollAnimations();
  new FAQAccordion();
  new WorkflowAnimation();
  new ScoreAnimation();
  new FixSignalSimulator();
  new SmoothScroll();
  new MorphingButton();
  new NavigationActive();
  new LogoAnimation();
  new ParallaxEffect();

  // Add animation styles to sections
  const style = document.createElement('style');
  style.textContent = `
    .scroll-fade-in {
      animation: fadeInUp 0.8s ease-out var(--reveal-delay, 0ms) both;
    }

    .nav-link.active {
      color: var(--text-primary);
      font-weight: 700;
    }

    .feature-card,
    .step-card,
    .audience-card,
    .surface-node {
      opacity: 0;
    }

    .feature-card.scroll-fade-in,
    .step-card.scroll-fade-in,
    .audience-card.scroll-fade-in,
    .surface-node.scroll-fade-in {
      animation: fadeInUp 0.6s ease-out var(--reveal-delay, 0ms) both;
    }
  `;
  document.head.appendChild(style);

  console.log('Valorynn Landing Page Initialized');
});

// ===========================
// Handle Prefers Reduced Motion
// ===========================
const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
if (prefersReducedMotion) {
  document.documentElement.style.scrollBehavior = 'auto';
}
