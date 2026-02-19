# CertA Documentation Index

Complete documentation overview for the CertA Certification Authority system.

## 📚 Documentation Overview

CertA is a comprehensive Certification Authority system with user authentication, authorization, and certificate management capabilities. This documentation provides complete guidance for users, administrators, and developers.

## 🚀 Quick Start

### For New Users
1. **Read the [User Guide](USER_GUIDE.md)** - Complete end-user documentation
2. **Follow the [README](../README.md)** - Installation and basic setup
3. **Install Root CA** - Download and install the root CA certificate
4. **Create Your First Certificate** - Use the web interface to create certificates

### For Administrators
1. **Review [Deployment Guide](DEPLOYMENT.md)** - Production deployment instructions
2. **Study [Architecture Guide](ARCHITECTURE.md)** - System design and security
3. **Configure Authentication** - Set up user accounts and permissions
4. **Monitor System** - Implement logging and monitoring

### For Developers
1. **Examine [API Documentation](API.md)** - Complete API reference
2. **Understand [Architecture](ARCHITECTURE.md)** - Technical implementation details
3. **Review Security Model** - Authentication and authorization design
4. **Plan Extensions** - Future development roadmap

## 📖 Documentation Structure

### Core Documentation

#### [README](../README.md) - Main Project Documentation
- **Purpose**: Project overview and quick start guide
- **Audience**: All users
- **Content**: Features, installation, basic usage, configuration
- **Key Sections**:
  - 🌟 Features overview
  - 🚀 Quick start with Docker
  - 👤 User management guide
  - 📋 Certificate operations
  - 🔒 Security considerations

#### [User Guide](USER_GUIDE.md) - End-User Documentation
- **Purpose**: Complete user manual for CertA
- **Audience**: End users, certificate administrators
- **Content**: Step-by-step instructions for all user operations
- **Key Sections**:
  - 👤 User account management (registration, login, profile)
  - 📜 Certificate creation and management
  - 🏛️ Certificate Authority installation
  - 🔒 Security best practices
  - 🐛 Troubleshooting guide

#### [API Documentation](API.md) - Technical API Reference
- **Purpose**: Complete REST API reference
- **Audience**: Developers, system integrators
- **Content**: All API endpoints, authentication, data models
- **Key Sections**:
  - 🔐 Authentication endpoints (login, register, profile)
  - 📜 Certificate management APIs
  - 🏛️ CA management endpoints
  - 📊 Data models and schemas
  - 🛠️ Code examples (cURL, PowerShell)

#### [Architecture Guide](ARCHITECTURE.md) - Technical Architecture
- **Purpose**: System design and technical implementation
- **Audience**: Developers, architects, administrators
- **Content**: Detailed technical architecture and design decisions
- **Key Sections**:
  - 🏗️ System overview and layered architecture
  - 🔐 Authentication & authorization design
  - 📜 Certificate architecture and hierarchy
  - 🗄️ Database design and relationships
  - 🔒 Security architecture and best practices

#### [Keycloak (OAuth2) Authentication](KEYCLOAK.md) - External identity provider
- **Purpose**: Configure CertA and Keycloak for OAuth2 / OpenID Connect login
- **Audience**: Administrators, DevOps
- **Content**: Keycloak client setup, CertA configuration, Docker notes, troubleshooting
- **Key Sections**: Keycloak client and redirect URIs, CertA Authentication:Keycloak settings, SSL/PAR notes, first-login provisioning

#### [Deployment Guide](DEPLOYMENT.md) - Production Deployment
- **Purpose**: Production deployment and operations
- **Audience**: System administrators, DevOps engineers
- **Content**: Deployment strategies, monitoring, maintenance
- **Key Sections**:
  - 🐳 Docker deployment
  - ☸️ Kubernetes deployment
  - 🔒 Security hardening
  - 📊 Monitoring and logging
  - 🔄 Backup and recovery

## 🎯 Use Cases

### Individual Users
- **Personal Projects**: Create certificates for personal websites
- **Development**: SSL certificates for local development
- **Learning**: Understand certificate management concepts

### Small Organizations
- **Internal Infrastructure**: Certificates for internal services
- **Development Teams**: Shared certificate management
- **Testing**: Certificates for test environments

### Enterprise Organizations
- **Multi-User Management**: User isolation and access control
- **Compliance**: Certificate lifecycle management
- **Integration**: API-based certificate automation
- **Security**: Centralized certificate authority

## 🔑 Key Features

### 🔐 Authentication & Authorization
- **User Registration**: Self-service account creation
- **Secure Login**: Password-based authentication with session management
- **Keycloak (OAuth2)**: Optional login via Keycloak; see [Keycloak guide](KEYCLOAK.md)
- **User Isolation**: Each user can only access their own certificates
- **Profile Management**: User information and password updates
- **Session Security**: Configurable session timeouts and security

### 🏛️ Certificate Authority
- **Root CA Management**: Self-signed root certificate authority
- **CA-Signed Certificates**: Proper certificate hierarchy (not self-signed)
- **Trust Chain**: Install root CA to make all certificates trusted
- **Multiple Certificate Types**: Server, Client, Code Signing, Email
- **Subject Alternative Names**: Support for multiple domains per certificate

### 📜 Certificate Management
- **Web Interface**: User-friendly certificate creation and management
- **Multiple Formats**: PEM, PFX/PKCS#12 download options
- **Key Management**: Separate public and private key downloads
- **Certificate Details**: Comprehensive certificate information display
- **User Ownership**: Complete user isolation and data separation

### 🔧 Technical Features
- **Database Storage**: PostgreSQL with Entity Framework Core
- **Docker Support**: Complete containerization with Docker Compose
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **ACME Protocol**: Planned support for automated certificate management
- **API Access**: RESTful API for programmatic access

## 🛠️ Technology Stack

### Backend
- **Framework**: ASP.NET Core 9.0
- **Authentication**: ASP.NET Core Identity
- **Database**: PostgreSQL with Entity Framework Core
- **Cryptography**: .NET System.Security.Cryptography
- **Logging**: Serilog with structured logging

### Frontend
- **Framework**: ASP.NET Core MVC with Razor Views
- **UI Framework**: Bootstrap 5
- **Icons**: Bootstrap Icons
- **Validation**: Client-side and server-side validation

### Infrastructure
- **Containerization**: Docker and Docker Compose
- **Database**: PostgreSQL 15
- **Deployment**: Multi-environment support
- **Monitoring**: Health checks and logging

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **Docker**: Docker Desktop or Docker Engine
- **Browser**: Modern web browser (Chrome, Firefox, Safari, Edge)
- **Network**: Internet access for initial setup

### Development Requirements
- **.NET 9.0 SDK**: For local development
- **PostgreSQL**: For local database
- **IDE**: Visual Studio, VS Code, or JetBrains Rider
- **Git**: Version control

## 🔄 Workflow

### User Registration and Setup
1. **Access Application**: Navigate to CertA web interface
2. **Register Account**: Create user account with email and password
3. **Login**: Authenticate with credentials
4. **Install Root CA**: Download and install root CA certificate
5. **Create Certificates**: Start creating and managing certificates

### Certificate Lifecycle
1. **Certificate Creation**: Fill form with domain and certificate details
2. **CA Signing**: System automatically signs with root CA
3. **Download**: Download certificate in preferred format
4. **Installation**: Install on target system (web server, application)
5. **Management**: Monitor expiration and renew as needed

### Administrative Tasks
1. **User Management**: Monitor user accounts and activity
2. **CA Management**: Manage root CA certificate and settings
3. **System Monitoring**: Monitor logs, performance, and security
4. **Backup and Recovery**: Regular backups and disaster recovery

## 🔒 Security Model

### Authentication Security
- **Password Requirements**: Minimum 6 characters with complexity
- **Session Management**: 12-hour sessions with sliding expiration
- **Secure Cookies**: HTTP-only, secure cookie configuration
- **CSRF Protection**: Anti-forgery token validation

### Authorization Security
- **User Isolation**: Complete separation of user data
- **Access Control**: Users can only access their own resources
- **Permission Validation**: Server-side validation of all requests
- **Audit Logging**: Comprehensive operation logging

### Certificate Security
- **Private Key Protection**: Encrypted storage in database
- **Secure Downloads**: Protected download endpoints
- **CA Security**: Root CA private key protection
- **Trust Chain**: Proper certificate hierarchy validation

## 🐛 Common Tasks

### User Management
- **Create User Account**: Registration process and requirements
- **Update Profile**: Change personal information and password
- **Manage Sessions**: Login, logout, and session management
- **Access Control**: Understanding user isolation and permissions

### Certificate Operations
- **Create Certificate**: Step-by-step certificate creation
- **Download Formats**: Understanding PEM vs PFX formats
- **Install Certificates**: Platform-specific installation guides
- **Verify Installation**: Certificate validation and trust verification

### System Administration
- **Install Root CA**: Platform-specific CA installation
- **Monitor System**: Log analysis and performance monitoring
- **Backup Data**: Database and certificate backup procedures
- **Troubleshoot Issues**: Common problems and solutions

## 🚀 Troubleshooting

### Authentication Issues
- **Login Problems**: Password reset and account recovery
- **Session Issues**: Cookie and browser compatibility
- **Access Denied**: Understanding authorization requirements

### Certificate Issues
- **Trust Problems**: Root CA installation verification
- **Format Issues**: PEM vs PFX compatibility
- **Installation Errors**: Platform-specific troubleshooting
- **Validation Failures**: Certificate chain verification

### System Issues
- **Database Connection**: Connection string and network issues
- **Docker Problems**: Container startup and configuration
- **Performance Issues**: Resource monitoring and optimization
- **Security Concerns**: Security configuration and hardening

## 🗺️ Roadmap

### Planned Features
- **ACME Protocol**: RFC 8555 implementation for automated certificate management
- **Certificate Revocation**: CRL and OCSP responder support
- **Intermediate CAs**: Multi-level certificate authority hierarchy
- **API Authentication**: JWT token-based API access
- **Certificate Monitoring**: Expiration alerts and renewal automation

### Security Enhancements
- **Multi-Factor Authentication**: MFA support for enhanced security
- **Role-Based Access Control**: Advanced authorization with roles
- **Hardware Security Modules**: HSM integration for key management
- **Certificate Transparency**: CT log integration for monitoring

### Integration Features
- **Web Server Integration**: Apache, Nginx, IIS integration
- **Load Balancer Support**: HAProxy, F5, cloud load balancers
- **Cloud Platform Integration**: AWS, Azure, GCP integration
- **Monitoring Integration**: Prometheus, Grafana, ELK Stack

## 🤝 Contributing

### Development Guidelines
- **Code Style**: Follow C# coding conventions
- **Testing**: Include unit and integration tests
- **Documentation**: Update relevant documentation
- **Security**: Follow security best practices

### Getting Help
- **Documentation**: Check relevant documentation sections
- **Issues**: Report bugs and feature requests
- **Discussions**: Ask questions and share ideas
- **Community**: Join the CertA community

## 📄 License and Support

### License
- **License**: GNU Lesser General Public License v3.0
- **Commercial Use**: Allowed with attribution
- **Modifications**: Allowed with license preservation
- **Distribution**: Allowed with source code inclusion

### Support
- **Community Support**: Documentation and community forums
- **Issue Tracking**: GitHub issues for bug reports
- **Feature Requests**: GitHub discussions for feature ideas
- **Security Issues**: Private security reporting

---

## 📞 Quick Reference

### Default Credentials
- **Admin Email**: `admin@certa.local`
- **Admin Password**: `Admin123!`
- **Database**: PostgreSQL (Docker)
- **Web Interface**: `http://localhost:8080`

### Common Commands
```bash
# Start CertA
docker-compose up -d

# View logs
docker-compose logs -f

# Stop CertA
docker-compose down

# Rebuild containers
docker-compose build --no-cache
```

### Important URLs
- **Web Interface**: `http://localhost:8080`
- **Login Page**: `http://localhost:8080/Account/Login`
- **Certificate Authority**: `http://localhost:8080/Certificates/Authority`
- **My Certificates**: `http://localhost:8080/Certificates` (requires login)

---

**CertA Documentation** - Complete guide for secure certificate authority management

*Last updated: August 2025*
