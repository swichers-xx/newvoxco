# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Voxco Server Monitoring Dashboard seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly**
2. **Email the details to security@example.com**
   - Provide a detailed description of the vulnerability
   - Include steps to reproduce the issue
   - Attach any proof-of-concept code or screenshots if applicable
   - Let us know if and how you'd like to be credited

## Security Best Practices

When deploying this application, please follow these security best practices:

1. **Change Default Credentials**
   - Always change the default admin username and password in the `.env` file
   - Use strong, unique passwords

2. **Use HTTPS**
   - Configure a reverse proxy with SSL/TLS for production deployments
   - Redirect HTTP traffic to HTTPS

3. **Secure WinRM**
   - Use dedicated service accounts with limited permissions for WinRM
   - Consider using HTTPS for WinRM connections
   - Implement network-level restrictions for WinRM access

4. **Regular Updates**
   - Keep the application and its dependencies updated
   - Apply security patches promptly

5. **Access Control**
   - Restrict access to the dashboard using firewalls or VPNs
   - Implement IP-based access restrictions when possible

6. **Audit Logging**
   - Enable and monitor audit logs
   - Regularly review access logs for suspicious activity

## Security Features

The Voxco Server Monitoring Dashboard includes several security features:

- JWT-based authentication
- Configurable token expiration
- Secure credential storage
- Role-based access control (when configured)