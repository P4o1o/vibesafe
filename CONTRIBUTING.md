# Contributing to VibeSafe 🛡️

Thanks for your interest in improving VibeSafe!  
We're an open-source security CLI built for developers — fast, useful, and community-driven.

Whether you're fixing a typo, improving performance, adding new scanners, or suggesting a feature, we welcome your input.

---

## 💡 How to Contribute

1. **Fork the repo**
2. **Clone your fork and create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Run tests** (if applicable)
5. **Open a Pull Request (PR)** with a clear description of what you changed and why

## 📏 Guidelines
Keep PRs focused and minimal — smaller is better

Avoid introducing new dependencies unless absolutely necessary

Write clear, readable code (preferably TypeScript where applicable)

Add comments or docs for any non-obvious logic

If adding a new scanner or rule, explain the security impact or use case

## 🧪 Testing (Basic)
Most of VibeSafe is modular and easy to test with sample files.
You can test your changes by running:

```bash
npm run build
npm link
vibesafe scan ./test-project
```

If you're improving output formats or adding rules, try --output and --report modes to check formatting.

## 📛 Brand Reminder
The name VibeSafe™ is a trademark of Secret Society LLC.
Forks and derivative tools are welcome under the MIT License, but please use a different name and logo for your project.

If you'd like to collaborate, contribute under the official name, or build something commercial on top of VibeSafe, reach out:
📬 vibesafepackage@gmail.com

## 🤝 Code of Conduct
Be respectful. This project is about making security tools accessible, not gatekeeping. We welcome newcomers, learners, and veterans alike.

## 🚀 Ready to go?
Open your PR, and let's make security more developer-friendly — together.

Stay safe. Stay vibey. ✨