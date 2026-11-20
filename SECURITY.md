# **Reporting a Security Vulnerability or Incident**

Please do not report security vulnerabilities or security incidents via public channels (such as GitHub Issues or Pull Requests, GitLab Merge Requests). To ensure coordinated disclosure, submit your findings via email to: secalert@redhat.com

## **Submission Guidelines**

To help us triage and resolve the issue efficiently, please include the following in your report:

- **Title**: A concise, descriptive summary of the issue.
- **Reporter Details**: Your name/handle and affiliation.
- **Technical Description**: Detailed information regarding the vulnerability.
- **Affected Versions**: The specific version(s) or range(s) of software tested.
- **Reproduction Steps**: A minimal, functional example to reproduce the issue.
- **Impact Assessment**: Potential exploit scenarios and perceived severity. (optional)
- **Suggested Fix**: Any proposed patches or mitigations (optional).
- **Disclosure Status**: Whether this has been shared with other parties or published and your plan for future sharing (e.g., at a conference).

## **Response Timeline**

We aim to provide an initial acknowledgement of your report within 3 days.

Our goal is to assess the report, coordinate fix and disclosure as quickly as possible. All confirmed security vulnerabilities and incidents will be addressed according to severity level and impact on the project.

## **Contact Information**

Direct all security questions and vulnerability reports to:

- **Email**: secalert@redhat.com
- Further details **GPG key ID** and fingerprint: https://access.redhat.com/security/team/contact

## **Supported Versions**

Patches are provided for the supported latest versions listed on the [SSSD releases page](https://sssd.io/releases.html), which contain fixes for relevant security vulnerabilities and important bugs. Prior releases might receive critical security fixes on a best-effort basis. However, we cannot guarantee that security fixes will get back-ported to these unsupported versions.

## **Incident Response Policy**

### **Scope**

The "Incident Response Policy" covers security incidents affecting this project, including its source code, infrastructure, release pipeline, maintainer accounts, and contributor trust.

Security takes place in two places - before and after something goes wrong. Other processes and policy should be in place to be preventative and cover things like reviewing merge requests before they are accepted, and vetting new contributions and contributors to a project before they are trusted. This "Incident Response Policy", or IRP, is reactive and covers what happens if something has already gone wrong.

### **What constitutes an incident**

An incident can be many things.  In this context we are talking about hostile events that threaten the security of the product.
- Unauthorized code changes (e.g. a malicious commit or compromised maintainer account)
- Leaked secrets, credentials, or signing keys
- A vulnerability being actively exploited in the wild
- Compromised build or release infrastructure
- A compromised endpoint belonging to someone with repository or release access

### **Reporting an incident**

- Report to: secalert@redhat.com
- Never open a public issue for an active exploit or a leaked secret
- We aim to acknowledge all reports within 3 business days

### **Response process**

1. **Triage** — Confirm the incident, assess its scope and severity.
2. **Contain** — Revoke credentials, roll back affected commits, pull releases, rotate keys as needed.
3. **Eradicate** — Fix the root cause and patch the vulnerability.
4. **Recover** — Restore normal operations; re-issue a release on github if required an add it to the [SSSD releases page](https://sssd.io/releases.html).
5. **Disclose** — Notify affected users and publish an advisory, following coordinated disclosure practices.
6. **Review** — Conduct a post-incident review and document follow-up actions to prevent recurrence.

## **EU Cyber Resilience Act — Open Source Steward Statement**

This project is stewarded by **Red Hat, Inc.**, an open source software steward as defined in Article 3(14) of the [EU Cyber Resilience Act (Regulation 2024/2847)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng).
Contact: [cra-steward@redhat.com](mailto:cra-steward@redhat.com)

Refer to [Red Hat's security practices and vulnerability management policy](https://access.redhat.com/security/) for detailed information.
