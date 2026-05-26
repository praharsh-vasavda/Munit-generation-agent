# MUnit Generation Agent

A Python-based AI agent that generates MUnit test suites for MuleSoft applications by analyzing Mule XML files and business use case documents.

## Features

- **Multi-Source Input**: Support for local files, GitHub repositories, and Confluence pages
- **Intelligent Analysis**: Extracts flow information, connectors, and patterns from Mule XML
- **Business Scenario Parsing**: Extracts test scenarios from business documents (PDF, DOCX, TXT)
- **Multi-LLM Support**: Fallback chain across multiple LLM providers (Anthropic, OpenAI, Groq, Gemini, OpenRouter)
- **Rule-Based Generation**: YAML-based rulesets for consistent MUnit output
- **Token Optimization**: Smart prompt building to stay within model limits
- **XML Validation**: Ensures generated MUnit XML is well-formed and valid

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd munit-agent-poc
```

2. Install dependencies:
```bash
py -m pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys
```

### Configuration

Edit `.env` file with your API keys:

```bash
# LLM API Keys (at least one required)
ANTHROPIC_API_KEY=your_anthropic_key
OPENAI_API_KEY=your_openai_key
GROQ_API_KEY=your_groq_key
GEMINI_API_KEY=your_gemini_key
OPENROUTER_API_KEY=your_openrouter_key

# Optional: GitHub and Confluence
GITHUB_TOKEN=your_github_token
CONFLUENCE_TOKEN=your_confluence_token
CONFLUENCE_EMAIL=your_confluence_email
```

### Usage

#### Generate from Local Files

```bash
py main.py generate \
  --xml-source local \
  --xml-path ./myapp/src/main/mule/my-api.xml \
  --usecase-source local \
  --usecase-path ./docs/use-case.pdf \
  --output-path ./generated-tests/
```

#### Generate from GitHub and Confluence

```bash
py main.py generate \
  --xml-source github \
  --github-repo owner/repo-name \
  --github-branch main \
  --github-file-path src/main/mule/my-api.xml \
  --github-token ghp_xxxx \
  --usecase-source confluence \
  --confluence-url https://mycompany.atlassian.net/wiki/spaces/XX/pages/123456 \
  --confluence-token xxxx \
  --output-path ./generated-tests/
```

#### Configuration Management

```bash
# Show current configuration
py main.py config --show

# Validate configuration
py main.py config --validate

# Create .env template
py main.py config --create-env
```

## Architecture

### Project Structure

```
munit-agent-poc/
|
|-- main.py                 # CLI entry point
|-- config.py              # Configuration management
|-- requirements.txt        # Dependencies
|-- .env.example           # Environment template
|-- README.md              # This file
|
|-- rulesets/              # YAML rule files
|   |-- munit_structure.yaml
|   |-- mock_rules.yaml
|   |-- assertion_rules.yaml
|   |-- scenario_rules.yaml
|
|-- inputs/                # Input source modules
|   |-- github_fetcher.py
|   |-- local_reader.py
|   |-- confluence_reader.py
|
|-- core/                  # Core processing modules
|   |-- xml_analyzer.py
|   |-- doc_parser.py
|   |-- prompt_builder.py
|   |-- ruleset_loader.py
|
|-- llm/                   # LLM integration
|   |-- llm_router.py
|
|-- output/                # Output handling
|   |-- munit_writer.py
```

### Core Components

#### XML Analyzer (`xml_analyzer.py`)
- Parses Mule XML files
- Detects job types (REST API, Batch Job, Scheduler, etc.)
- Extracts flows, connectors, transformers, and error handlers
- Identifies external HTTP endpoints

#### Document Parser (`doc_parser.py`)
- Supports PDF, DOCX, and TXT formats
- Extracts business scenarios and test cases
- Generates default scenarios based on job type if none found
- Identifies business rules and validation requirements

#### Prompt Builder (`prompt_builder.py`)
- Builds optimized prompts for LLM generation
- Token counting and optimization
- Ensures prompt stays within model limits
- Structured prompt format for consistent output

#### LLM Router (`llm_router.py`)
- Multi-LLM fallback chain
- XML validation and correction
- Retry logic with exponential backoff
- Model status monitoring

#### MUnit Writer (`munit_writer.py`)
- XML cleaning and formatting
- Pretty-printing with proper indentation
- File naming conventions
- Structure validation

## Supported Job Types

- **REST API**: HTTP listener-based flows
- **Batch Job**: Batch processing jobs
- **Scheduler**: Scheduled task flows
- **MQ Consumer**: Anypoint MQ and Kafka consumers
- **SFTP Listener**: SFTP file-based flows
- **Generic Mule Flow**: Default for other patterns

## Scenario Types

### REST API
- Happy path (successful execution)
- Empty payload validation
- Downstream API failure
- Invalid input validation

### Batch Job
- All records success
- Partial record failure
- Empty input handling
- All records failure

### Scheduler
- Normal execution
- Downstream failure

### MQ Consumer
- Valid message processing
- Malformed message handling
- Downstream processing failure

### SFTP Listener
- Valid file processing
- Empty file handling
- Malformed file content

## LLM Fallback Chain

1. **Anthropic Claude Sonnet 4** (primary)
2. **OpenAI GPT-4o**
3. **Groq Llama3 70B**
4. **Google Gemini 1.5 Pro**
5. **OpenRouter Mixtral 8x7B**

## Error Handling

The agent handles these error scenarios gracefully:

- GitHub file not found or authentication issues
- Confluence page access problems
- Invalid document formats
- Malformed Mule XML
- LLM API failures with automatic fallback
- XML validation errors with correction attempts
- Token limit exceeded with prompt optimization

## Output Format

Generated MUnit XML follows this structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xsi:schemaLocation="...">

    <munit:config name="test-suite"/>

    <munit:test name="test-flow-name-scenario" description="Test description">
        <munit:behavior>
            <!-- Mock definitions -->
        </munit:behavior>
        <munit:execution>
            <!-- Flow execution -->
        </munit:execution>
        <munit:validation>
            <!-- Assertions -->
        </munit:validation>
    </munit:test>

</mule>
```

## Customization

### Adding New Job Types

1. Update `rulesets/scenario_rules.yaml` with new job type scenarios
2. Add job type detection logic in `core/xml_analyzer.py`
3. Update scenario generation in `core/doc_parser.py`

### Modifying Rulesets

Edit YAML files in `rulesets/` directory:

- **munit_structure.yaml**: XML structure and naming conventions
- **mock_rules.yaml**: Mock strategies for different connectors
- **assertion_rules.yaml**: Assertion requirements per scenario type
- **scenario_rules.yaml**: Mandatory scenarios per job type

### Adding New LLM Providers

1. Update model chain in `llm/llm_router.py`
2. Add API key to `.env.example`
3. Update configuration validation in `config.py`

## Troubleshooting

### Common Issues

**"No LLM API keys configured"**
- Set at least one API key in `.env` file
- Run `py main.py config --validate` to check

**"Invalid Mule XML file"**
- Ensure XML file is a valid Mule application
- Check for proper Mule namespaces

**"GitHub file not found"**
- Verify repository URL format (owner/repo-name)
- Check file path and branch name
- Ensure GitHub token has proper permissions

**"Confluence page access denied"**
- Verify Confluence URL and page ID
- Check API token and email credentials
- Ensure proper Confluence permissions

### Debug Mode

Use `--verbose` flag for detailed output:

```bash
py main.py generate --verbose [other-options]
```

### Logs and Monitoring

The agent provides detailed console output including:
- Configuration status
- File processing progress
- LLM model usage and fallbacks
- Generation timing and token counts
- Validation results

## Requirements

- Python 3.8+ (compatible with `py` command)
- See `requirements.txt` for all dependencies
- **No Rust compiler required** - tiktoken dependency removed
- Optional: LLM API keys for AI-powered generation (Anthropic, OpenAI, Groq, Gemini, or OpenRouter)
- Optional: GitHub token for private repositories
- Optional: Confluence credentials for business documents

**Note**: The application now works without external LLM APIs using template-based generation.

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the configuration validation output
3. Use verbose mode for detailed debugging
4. Check that all prerequisites are met
