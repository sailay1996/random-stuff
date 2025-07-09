# Bug Bounty MCP Agent - System Architecture

## Overview

The Bug Bounty MCP Agent is a modular, extensible system built on the Model Context Protocol (MCP) framework. It provides a comprehensive suite of reconnaissance, scanning, intelligence gathering, and reporting capabilities for bug bounty hunters and security researchers.

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Bug Bounty MCP Agent                        │
├─────────────────────────────────────────────────────────────────┤
│                      Agent Controller                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Workflow      │  │   Task Queue    │  │   Result        │ │
│  │   Orchestrator  │  │   Manager       │  │   Aggregator    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                     MCP Server Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ ✅ Reconnaissance│  │ 🔄 Scanning     │  │ 🔄 Intelligence │ │
│  │    Server       │  │    Server       │  │    Server       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐                                           │
│  │ 🔄 Reporting    │                                           │
│  │    Server       │                                           │
│  └─────────────────┘                                           │
├─────────────────────────────────────────────────────────────────┤
│                    External Tools Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   DNS Tools     │  │   Port Scanners │  │   Web Crawlers  │ │
│  │ subfinder,amass │  │  nmap, masscan  │  │  gospider, etc  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 System Components

### 1. Agent Controller (Future Implementation)
- **Workflow Orchestrator**: Manages multi-phase reconnaissance workflows
- **Task Queue Manager**: Handles asynchronous task execution and prioritization
- **Result Aggregator**: Consolidates results from multiple MCP servers

### 2. MCP Server Layer

#### ✅ Reconnaissance Server (Implemented)
**Location**: `/mcp-servers/recon/`

**Purpose**: Primary reconnaissance and information gathering

**Components**:
- `recon_server.py` - Main MCP server implementation
- `dns_utils.py` - DNS resolution and subdomain validation
- `port_scanner.py` - Port discovery and service detection
- `config.py` - Configuration management

**Available Tools**:
1. `enumerate_subdomains` - Multi-tool subdomain discovery
2. `resolve_dns` - DNS record resolution
3. `discover_ports` - Port scanning and service detection

#### 🔄 Scanning Server (Planned)
**Location**: `/mcp-servers/scan/`

**Purpose**: Vulnerability scanning and security assessment

**Planned Tools**:
- `web_scan` - Web application vulnerability scanning
- `network_scan` - Network-level security assessment
- `service_scan` - Service-specific vulnerability detection

#### 🔄 Intelligence Server (Planned)
**Location**: `/mcp-servers/intel/`

**Purpose**: OSINT and threat intelligence gathering

**Planned Tools**:
- `osint_gather` - Open source intelligence collection
- `threat_intel` - Threat intelligence correlation
- `social_recon` - Social media and public information gathering

#### 🔄 Reporting Server (Planned)
**Location**: `/mcp-servers/report/`

**Purpose**: Report generation and data visualization

**Planned Tools**:
- `generate_report` - Comprehensive report generation
- `export_data` - Data export in multiple formats
- `visualize_results` - Data visualization and charts

## 🔄 Reconnaissance Phase Architecture (Implemented)

### Data Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Target Input  │───▶│  Subdomain      │───▶│   DNS           │
│   (domain.com)  │    │  Enumeration    │    │   Resolution    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                              ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  External Tools │    │   Live Hosts    │
                       │ subfinder,amass │    │   Validation    │
                       │ assetfinder,etc │    └─────────────────┘
                       └─────────────────┘             │
                              │                        ▼
                              ▼                ┌─────────────────┐
                       ┌─────────────────┐    │   Port          │
                       │   Subdomain     │───▶│   Discovery     │
                       │   Results       │    │   & Service     │
                       │   Aggregation   │    │   Detection     │
                       └─────────────────┘    └─────────────────┘
                              │                        │
                              ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Deduplicated  │    │   Open Ports    │
                       │   Subdomains    │    │   & Services    │
                       └─────────────────┘    └─────────────────┘
```

### Component Details

#### DNS Resolution Engine
**File**: `dns_utils.py`

**Architecture**:
```python
class DNSResolver:
    ├── __init__(resolvers, timeout, max_workers)
    ├── resolve_domain(domain, record_types)
    ├── resolve_bulk(domains, record_types)
    ├── filter_live_subdomains(subdomains)
    └── _resolve_single(domain, record_type)
```

**Features**:
- Asynchronous DNS resolution using `aiodns`
- Multiple DNS resolver support (8.8.8.8, 1.1.1.1)
- Bulk domain processing with concurrency control
- Support for A, AAAA, CNAME, MX, TXT, NS, SOA records
- Live subdomain filtering

#### Port Scanning Engine
**File**: `port_scanner.py`

**Architecture**:
```python
class PortScanner:
    ├── __init__(timeout, max_concurrent)
    ├── scan_host(host, ports, protocols)
    ├── scan_multiple_hosts(hosts, ports, protocols)
    ├── _scan_tcp_port(host, port)
    ├── _scan_udp_port(host, port)
    ├── _detect_service(host, port, protocol)
    └── _parse_port_specification(port_spec)
```

**Features**:
- Asynchronous TCP/UDP port scanning
- Service detection and banner grabbing
- Flexible port specification (ranges, lists, presets)
- Configurable concurrency and timeouts
- Common service identification

#### Configuration Management
**File**: `config.py`

**Architecture**:
```python
class ReconConfig:
    ├── __init__(config_path)
    ├── load_config()
    ├── validate_config()
    ├── get_tool_path(tool_name)
    └── _merge_env_vars()
```

**Configuration Hierarchy**:
1. Default configuration (hardcoded)
2. YAML configuration file
3. Environment variables (highest priority)

### External Tool Integration

#### Subdomain Enumeration Tools

**Supported Tools**:
- **subfinder**: Fast passive subdomain enumeration
- **amass**: Comprehensive OSINT subdomain discovery
- **assetfinder**: Simple subdomain finder
- **sublist3r**: Python-based subdomain enumeration

**Integration Pattern**:
```python
async def run_tool(tool_name, domain, config):
    ├── Validate tool availability
    ├── Build command with parameters
    ├── Execute subprocess with timeout
    ├── Parse and standardize output
    └── Return structured results
```

## 🔧 Configuration Architecture

### Configuration Files

#### Main Configuration
**File**: `config/config.example.yaml`

```yaml
server:
  name: "recon-mcp-server"
  version: "1.0.0"
  
dns:
  timeout: 5.0
  max_workers: 50
  resolvers:
    - "8.8.8.8"
    - "1.1.1.1"
    
port_scan:
  timeout: 3.0
  max_concurrent: 100
  default_ports: "top-1000"
  
tools:
  subfinder:
    path: "/usr/local/bin/subfinder"
    timeout: 300
  amass:
    path: "/usr/local/bin/amass"
    timeout: 600
    
rate_limiting:
  requests_per_second: 10
  burst_size: 20
```

### Environment Variables

```bash
# Configuration
RECON_CONFIG_PATH=/path/to/config.yaml

# DNS Settings
DNS_TIMEOUT=5.0
DNS_RESOLVERS=8.8.8.8,1.1.1.1

# Port Scanning
PORT_SCAN_TIMEOUT=3.0
PORT_SCAN_CONCURRENT=100

# Tool Paths
SUBFINDER_PATH=/usr/local/bin/subfinder
AMASS_PATH=/usr/local/bin/amass
ASSETFINDER_PATH=/usr/local/bin/assetfinder
SUBLIST3R_PATH=/usr/local/bin/sublist3r
```

## 🚀 Deployment Architecture

### Development Environment
```
bugbounty-mcp-agent/
├── mcp-servers/recon/
│   ├── start_server.py      # Development server
│   ├── demo.py              # Interactive demo
│   └── test_*.py            # Test suites
```

### Production Environment (Planned)
```
/opt/bugbounty-mcp-agent/
├── bin/
│   ├── recon-server         # Production binary
│   ├── scan-server          # Scanning server
│   └── agent-controller     # Main controller
├── config/
│   ├── production.yaml      # Production config
│   └── logging.yaml         # Logging config
├── logs/
└── data/
    ├── wordlists/
    └── results/
```

## 🔒 Security Architecture

### Input Validation
- Domain name validation using regex patterns
- IP address validation using `ipaddress` module
- Port range validation (1-65535)
- Command injection prevention

### Rate Limiting
- Request rate limiting per target
- Burst protection mechanisms
- Timeout enforcement
- Resource usage monitoring

### Error Handling
- Graceful failure modes
- Detailed error logging
- Resource cleanup on exceptions
- Isolation between tool executions

## 📊 Performance Architecture

### Asynchronous Design
- All I/O operations use `async/await`
- Concurrent DNS resolution
- Parallel port scanning
- Non-blocking subprocess execution

### Resource Management
- Configurable concurrency limits
- Memory-efficient streaming for large datasets
- Connection pooling for DNS resolvers
- Automatic cleanup of temporary resources

### Scalability Considerations
- Horizontal scaling through multiple server instances
- Load balancing for high-volume operations
- Result caching for repeated queries
- Batch processing for bulk operations

## 🔮 Future Architecture Enhancements

### Phase 2: Scanning Server
- Integration with nmap, masscan, nuclei
- Vulnerability database correlation
- Custom payload generation
- Result prioritization and scoring

### Phase 3: Intelligence Server
- OSINT data aggregation
- Threat intelligence feeds
- Social media monitoring
- Dark web monitoring

### Phase 4: Reporting Server
- Multi-format report generation (PDF, HTML, JSON)
- Data visualization and charts
- Executive summary generation
- Integration with ticketing systems

### Phase 5: Agent Controller
- Workflow orchestration
- Multi-target campaign management
- Real-time monitoring and alerting
- API gateway for external integrations

## 🧪 Testing Architecture

### Test Structure
```
tests/
├── unit/
│   ├── test_dns_utils.py
│   ├── test_port_scanner.py
│   └── test_config.py
├── integration/
│   ├── test_recon_server.py
│   └── test_tool_integration.py
├── performance/
│   ├── test_load.py
│   └── test_concurrency.py
└── fixtures/
    ├── sample_domains.txt
    └── test_config.yaml
```

### Testing Strategies
- **Unit Tests**: Individual component testing
- **Integration Tests**: MCP server functionality
- **Performance Tests**: Load and stress testing
- **Security Tests**: Input validation and injection prevention
- **End-to-End Tests**: Complete workflow validation

## 📈 Monitoring and Observability

### Logging Architecture
- Structured logging using JSON format
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Centralized log aggregation
- Performance metrics collection

### Metrics Collection
- Request/response times
- Success/failure rates
- Resource utilization
- Tool execution statistics

### Health Checks
- Server health endpoints
- External tool availability checks
- DNS resolver connectivity
- Configuration validation

## 🔗 Integration Points

### MCP Protocol Compliance
- Standard MCP server interface implementation
- `list_tools` and `call_tool` request handling
- Proper error response formatting
- Async/await pattern for non-blocking operations

### External System Integration
- REST API endpoints for external tools
- Database integration for result storage
- Message queue integration for async processing
- Webhook support for real-time notifications

## 📝 Development Guidelines

### Code Organization
- Modular design with clear separation of concerns
- Consistent naming conventions
- Comprehensive documentation
- Type hints for better code clarity

### Error Handling Patterns
- Custom exception classes for different error types
- Graceful degradation when tools are unavailable
- Retry mechanisms with exponential backoff
- Detailed error logging and reporting

### Configuration Management
- Environment-specific configurations
- Validation of all configuration parameters
- Hot-reload capability for configuration changes
- Secure handling of sensitive configuration data

This architecture provides a solid foundation for the Bug Bounty MCP Agent system, with the reconnaissance phase fully implemented and clear pathways for extending the system with additional capabilities.
