"""
PHANTOM — Google Dork Generator Module
Generates Google dork queries for the target. NO actual Google searching.
"""
from urllib.parse import quote


class DorkGen:
    """Google dork query generator for target domains."""

    name = "dorks"
    description = "Google dork query generation"

    # (name, query_template) pairs
    DORKS = [
        # ── Information disclosure ──
        ("Directory listing",
         "site:{domain} intitle:\"index of\""),
        ("Directory listing - parent",
         "site:{domain} intitle:\"index of /\" parent directory"),
        ("Configuration files exposed",
         "site:{domain} (ext:xml | ext:conf | ext:cfg | ext:env | ext:ini | ext:config)"),
        ("Database files exposed",
         "site:{domain} (ext:sql | ext:db | ext:sqlite | ext:mdb | ext:accdb)"),
        ("Log files exposed",
         "site:{domain} (ext:log | ext:txt ext:log | ext:out)"),
        ("Backup files exposed",
         "site:{domain} (ext:bak | ext:old | ext:backup | ext:swp | ext:save | ext:orig)"),
        ("Error messages",
         "site:{domain} (\"PHP Fatal error\" | \"Notice: Undefined\" | \"Warning: mysql\" | \"SQL syntax\" | \"ORA-\" | \"Parse error\")"),
        ("PHP info pages",
         "site:{domain} (ext:php intitle:phpinfo | \"phpinfo()\" | \"PHP Version\")"),

        # ── Exposed admin panels ──
        ("Admin login pages",
         "site:{domain} (inurl:admin | inurl:login | inurl:wp-admin | inurl:cpanel | inurl:dashboard)"),
        ("cPanel/WHM access",
         "site:{domain} (inurl:cpanel | inurl:whm | intitle:\"cPanel Login\" | intitle:\"WebHost Manager\")"),
        ("phpMyAdmin",
         "site:{domain} (inurl:phpmyadmin | intitle:phpMyAdmin | inurl:pma)"),

        # ── Sensitive data ──
        ("Password files",
         "site:{domain} (ext:pwd | ext:passwd | ext:htpasswd | ext:htaccess | inurl:\".htpasswd\" | inurl:\".htaccess\")"),
        ("Private keys & certificates",
         "site:{domain} (ext:key | ext:pem | ext:ppk | ext:cert | ext:crt | ext:p12 | ext:pfx)"),
        ("Environment files",
         "site:{domain} (ext:env | filename:.env | filename:.env.production | filename:.env.local)"),
        ("AWS keys",
         "site:{domain} (inurl:aws | ext:aws | \"aws_access_key\" | \"aws_secret_key\" | \"AKIA\")"),
        ("Docker configuration",
         "site:{domain} (ext:dockerfile | ext:docker-compose | filename:docker-compose.yml)"),

        # ── Version control ──
        ("Git repositories",
         "site:{domain} (inurl:.git | intitle:\"Git\" inurl:git)"),
        (".git/config exposed",
         "site:{domain} inurl:\".git/config\""),
        ("SVN repositories",
         "site:{domain} (inurl:.svn | inurl:\".svn/entries\")"),

        # ── File types (document discovery) ──
        ("PDF documents",
         "site:{domain} ext:pdf"),
        ("Office documents",
         "site:{domain} (ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx)"),
        ("Spreadsheets / CSVs",
         "site:{domain} (ext:xls | ext:xlsx | ext:csv)"),
        ("Text files",
         "site:{domain} ext:txt ext:txt"),
        ("JSON data files",
         "site:{domain} (ext:json | inurl:api ext:json)"),
        ("XML files",
         "site:{domain} ext:xml"),

        # ── URLs with parameters (injection points) ──
        ("PHP pages with parameters",
         "site:{domain} inurl:\"?\" ext:php"),
        ("ASP/ASPX pages with parameters",
         "site:{domain} inurl:\"?\" (ext:asp | ext:aspx)"),
        ("JSP pages with parameters",
         "site:{domain} inurl:\"?\" ext:jsp"),
        ("All pages with parameters",
         "site:{domain} inurl:\"&\""),

        # ── Specific services ──
        ("WordPress sites",
         "site:{domain} (inurl:wp-content | inurl:wp-includes | inurl:wp-json | intitle:\"WordPress\")"),
        ("Joomla sites",
         "site:{domain} (inurl:/components/ | inurl:/modules/ | inurl:/templates/)"),
        ("Drupal sites",
         "site:{domain} (inurl:/node/ | inurl:/user/ | \"Drupal\")"),
        ("Magento sites",
         "site:{domain} (inurl:/skin/ | inurl:/media/ | inurl:/downloader/)"),

        # ── Intranet / internal ──
        ("Intranet pages",
         "site:{domain} (intranet | internal)"),
        ("Employee portals",
         "site:{domain} (inurl:portal | inurl:employee | inurl:staff)"),
        ("SSO pages",
         "site:{domain} (inurl:sso | inurl:oauth | inurl:auth | inurl:login)"),

        # ── Security issues ──
        ("Open redirects",
         "site:{domain} inurl:redirect | inurl:url= | inurl:next= | inurl:return= | inurl:dest= | inurl:goto="),
        ("Exposed API endpoints",
         "site:{domain} (inurl:/api/ | inurl:/v1/ | inurl:/rest/ | inurl:/swagger)"),
        ("Jenkins instances",
         "site:{domain} (intitle:\"Jenkins\" | inurl:/jenkins/ | intitle:\"Dashboard [Jenkins]\")"),
        ("S3 buckets",
         "site:{domain} (s3 | bucket | .s3.amazonaws.com)"),
        ("WebDAV",
         "site:{domain} inurl:webdav | intitle:\"webdav\" | \"webdav\" directory"),

        # ── Debug / testing ──
        ("Test environments",
         "site:{domain} (inurl:test | inurl:dev | inurl:staging | inurl:sandbox)"),
        ("Debug pages",
         "site:{domain} (intitle:\"debug\" | inurl:debug | intitle:\"console\")"),
        ("PHP shell access",
         "site:{domain} (inurl:shell.php | inurl:cmd.php | inurl:exec.php | intitle:\"shell\")"),
    ]

    def __init__(self, engine):
        self.engine = engine
        self.target = engine.target
        self.config = engine.config

    def run(self):
        domain = self.target.domain
        if not domain:
            print("  [!] DorkGen: no domain set")
            return

        print(f"[*] Generating Google dorks for {domain}")

        results = []
        for name, query_template in self.DORKS:
            query = query_template.format(domain=domain)
            search_url = f"https://www.google.com/search?q={quote(query)}"

            entry = {
                "name": name,
                "query": query,
                "url": search_url,
                "description": name,
            }
            results.append(entry)

            print(f"  [+] {name}")
            print(f"      q: {query[:100]}{'...' if len(query) > 100 else ''}")

        self.target.dork_results = results
        self.target.add_timeline("recon", "dorks_generated",
                                 f"{len(results)} dork queries")
        print(f"  [*] Dork generation done: {len(results)} queries generated")
        print(f"  [*] Copy the queries above into Google search manually")
        print(f"  [*] Google blocks automated dorking — manual review required")
