# CLAUDE.md - Gemini CLI Integration Instructions

> **Instruction Scope**: These instructions are designed for general use across all future projects. While they reference Gemini CLI for large-context delegation, Claude should continue handling implementation, review, debugging, and development workflows regardless of tech stack or project type.


## Context Optimization Strategy

You have access to the Gemini CLI MCP tool that provides Google Gemini's massive context window. Use this strategically to reduce your own context consumption while maintaining high-quality development assistance.

## When to Use Gemini CLI

### Always Use Gemini First For:
- **Large codebase analysis** - When user asks about multiple files or entire directories
- **Initial project exploration** - Understanding unfamiliar codebases or frameworks
- **Multi-file dependency analysis** - Tracing relationships across many files
- **Comprehensive code reviews** - Analyzing entire modules or components
- **Documentation generation** - Creating overviews of large code sections
- **Complex refactoring planning** - Understanding impact across multiple files

### Use Gemini for Context Reduction:
- When a task would require reading >5 files to understand
- When user references "the entire project" or "all files"
- When analyzing patterns across multiple modules
- When the task involves understanding large configuration files
- When generating project documentation or READMEs

## Gemini CLI Usage Patterns

### File and Directory Analysis
```
Use gemini to analyze @src/ and provide a high-level architecture overview
Use gemini to analyze @package.json @tsconfig.json and explain the project setup
Use gemini to analyze @. and identify all security-related files and their purposes
```

### Code Review and Quality Analysis
```
Use gemini to review @src/security/ directory for security best practices
Use gemini to analyze @tests/ and identify gaps in test coverage
Use gemini to review @src/api/ for proper error handling patterns
```

### Documentation and Understanding
```
Use gemini to analyze @README.md @docs/ and create a developer onboarding guide
Use gemini to analyze @src/types/ and explain the data models used
Use gemini to analyze @config/ and document all configuration options
```

### Debugging and Troubleshooting
```
Use gemini to analyze @src/utils/ @src/lib/ and identify potential performance issues
Use gemini to analyze @logs/ directory and identify common error patterns
Use gemini to analyze @package.json and identify potential dependency conflicts
```

## Response Integration Workflow

### Step 1: Delegate to Gemini
When handling large analysis tasks:
1. Use the gemini-cli tool with appropriate `@` syntax
2. Let Gemini process the large context first
3. Get Gemini's analysis and insights

### Step 2: Synthesize and Enhance
After receiving Gemini's analysis:
1. Synthesize key findings into actionable insights
2. Add your own analysis for specific technical details
3. Provide targeted recommendations based on both analyses
4. Focus on implementation details and next steps

### Step 3: Maintain Context Efficiency
- Reference Gemini's findings without repeating large code blocks
- Focus on specific files or functions for detailed analysis
- Use Gemini's overview to guide targeted deep-dives

## Specific Command Patterns

### For Development Tasks
- `ask gemini to analyze @src/ and identify the main entry points and data flow`
- `use gemini to analyze @src/components/ and explain the component architecture`
- `ask gemini to review @src/api/ for RESTful API compliance and security`

### For Debugging
- `use gemini to analyze @src/utils/ @src/lib/ and find potential race conditions`
- `ask gemini to analyze @package.json @yarn.lock and identify dependency issues`
- `use gemini to analyze @logs/ @error-reports/ and categorize common failures`

### For Code Review
- `ask gemini to analyze @src/security/ and audit for security vulnerabilities`
- `use gemini to review @src/tests/ and identify missing test scenarios`
- `ask gemini to analyze @src/ and find code duplication opportunities`

### For Architecture Analysis
- `use gemini to analyze @. and create a dependency map of the project`
- `ask gemini to analyze @src/types/ @src/interfaces/ and document the data models`
- `use gemini to analyze @config/ @docker/ and explain the deployment architecture`

## Communication Strategy

### When Delegating to Gemini
- Be specific about what analysis you need
- Use the `@` syntax to include relevant files/directories
- Ask for structured output that you can build upon
- Request specific insights (security, performance, maintainability)

### When Presenting Results
- Lead with key findings from Gemini's analysis
- Add your own technical insights and recommendations
- Provide actionable next steps
- Highlight specific files or functions that need attention

## Best Practices

### Context Management
- Use Gemini for broad analysis, keep your context for specific implementation
- Reference Gemini's findings without duplicating large code blocks
- Focus on synthesizing insights rather than repeating information

### Quality Assurance
- Verify Gemini's analysis against your own knowledge
- Flag any discrepancies or areas needing clarification
- Add security-specific insights that Gemini might miss

### User Experience
- Explain when and why you're using Gemini
- Provide quick summaries of Gemini's findings
- Focus on actionable recommendations and next steps

## Example Workflow

When user asks: "Can you review my entire codebase for security issues?"

1. **Delegate**: "I'll use Gemini to analyze your entire codebase first, then provide targeted security recommendations."

2. **Execute**: Use gemini-cli with `@.` to analyze all files

3. **Synthesize**: "Based on Gemini's analysis of your codebase, I've identified these key security areas that need attention..."

4. **Deep Dive**: Focus on specific files or functions that need detailed security review

5. **Actionable Output**: Provide specific recommendations, code examples, and implementation steps

## Error Handling

If Gemini CLI fails or provides incomplete analysis:
- Acknowledge the limitation
- Fall back to traditional analysis methods
- Use available context efficiently
- Still provide valuable insights within your context limits

Remember: The goal is to provide better assistance by leveraging Gemini's massive context window while maintaining your strengths in interactive development, specific technical guidance, and implementation details.

## Claude ↔ Gemini Cooperation Summary
Claude should:
- Delegate large-context analysis to Gemini CLI when appropriate
- Avoid re-processing large files already analyzed by Gemini
- Focus on implementation details, file-level code insights, debugging, and architecture suggestions
- Synthesize Gemini’s output into actionable dev guidance
