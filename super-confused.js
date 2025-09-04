#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { promisify } = require('util');
const urlModule = require('url');

const readFile = promisify(fs.readFile);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

// ANSI color codes
const colors = {
    red: '\x1b[31m',
    reset: '\x1b[0m'
};

function colorize(text, color) {
    return colors[color] + text + colors.reset;
}

class SuperConfused {
    constructor(jsonMode = false) {
        this.results = [];
        this.jsonMode = jsonMode;
        this.supportedFiles = {
            'package.json': this.scanPackageJson,
            'requirements.txt': this.scanRequirementsTxt,
            'pyproject.toml': this.scanPyprojectToml,
            'go.mod': this.scanGoMod,
            'go.sum': this.scanGoSum,
            'Cargo.toml': this.scanCargoToml,
            'pom.xml': this.scanPomXml,
            'build.gradle': this.scanGradle,
            'composer.json': this.scanComposerJson,
            'Gemfile': this.scanGemfile,
            'yarn.lock': this.scanYarnLock,
            'package-lock.json': this.scanPackageLock,
            'bom.json': this.scanSbom,
            'sbom.json': this.scanSbom,
            'bom.xml': this.scanSbomXml,
            'sbom.xml': this.scanSbomXml
        };
        this.userAgent = 'SuperConfused/1.0';
        this.timeout = 10000; // Unified timeout: 10 seconds
        this.maxRedirects = 5; // Prevent infinite redirect loops
    }

    async scan(targetPath) {
        if (!this.jsonMode) {
            console.log(`Scanning ${targetPath} for dependency confusion opportunities...`);
        }

        if (targetPath.startsWith('http://') || targetPath.startsWith('https://')) {
            await this.scanUrl(targetPath);
        } else {
            const isDirectory = (await stat(targetPath)).isDirectory();

            if (isDirectory) {
                await this.scanDirectory(targetPath);
            } else {
                await this.scanFile(targetPath);
            }
        }

        this.printResults();
        return this.results;
    }

    async scanUrl(url) {
        try {
            // Convert GitHub/GitLab blob URLs to raw URLs
            let rawUrl = url;
            if (url.includes('github.com') && url.includes('/blob/')) {
                rawUrl = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
            } else if (url.includes('gitlab.com') && url.includes('/blob/')) {
                rawUrl = url.replace('/blob/', '/raw/');
            }

            const content = await this.fetchUrl(rawUrl);
            const fileName = this.getFileNameFromUrl(url);

            if (this.supportedFiles[fileName]) {
                const scanner = this.supportedFiles[fileName].bind(this);
                await scanner(url, content);
            } else {
                if (!this.jsonMode) {
                    console.error(`Unsupported file type: ${fileName}`);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error fetching URL ${url}: ${error.message}`);
            }
        }
    }

    getFileNameFromUrl(url) {
        const pathname = new URL(url).pathname;
        const fileName = pathname.split('/').pop();
        return fileName;
    }

    fetchUrl(url, redirectCount = 0) {
        if (redirectCount > this.maxRedirects) {
            throw new Error('Max redirects exceeded');
        }

        const parsedUrl = urlModule.parse(url);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;

        return new Promise((resolve, reject) => {
            const request = protocol.get(url, {
                timeout: this.timeout,
                headers: { 'User-Agent': this.userAgent }
            }, (response) => {
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    // Handle redirects (301, 302, 303, 307, 308)
                    this.fetchUrl(response.headers.location, redirectCount + 1).then(resolve).catch(reject);
                } else if (response.statusCode === 200) {
                    let data = '';
                    response.on('data', chunk => {
                        data += chunk;
                    });
                    response.on('end', () => {
                        resolve(data);
                    });
                } else {
                    reject(new Error(`HTTP ${response.statusCode}`));
                }
            });

            request.on('error', reject);
            request.on('timeout', () => {
                request.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    async scanDirectory(dirPath) {
        try {
            const entries = await readdir(dirPath);

            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry);
                const stats = await stat(fullPath);

                if (stats.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules') {
                    await this.scanDirectory(fullPath);
                } else if (stats.isFile() && this.supportedFiles[entry]) {
                    await this.scanFile(fullPath);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error scanning directory ${dirPath}: ${error.message}`);
            }
        }
    }

    async scanFile(filePath) {
        const fileName = path.basename(filePath);

        if (!this.supportedFiles[fileName]) {
            return;
        }

        try {
            const content = await readFile(filePath, 'utf8');
            const scanner = this.supportedFiles[fileName].bind(this);
            await scanner(filePath, content);
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error reading ${filePath}: ${error.message}`);
            }
        }
    }

    async scanPackageJson(filePath, content) {
        try {
            const packageData = JSON.parse(content);
            const dependencies = {
                ...packageData.dependencies,
                ...packageData.devDependencies,
                ...packageData.peerDependencies,
                ...packageData.optionalDependencies
            };

            await Promise.all(Object.entries(dependencies || {}).map(async ([name, version]) => {
                if (this.isPotentiallyVulnerable(name)) {
                    const exists = await this.checkNpmPackageExists(name);
                    this.addResult(filePath, 'npm', name, version, exists);
                }
            }));
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing package.json: ${error.message}`);
            }
        }
    }

    async scanPackageLock(filePath, content) {
        try {
            const lockData = JSON.parse(content);
            const dependencies = lockData.dependencies || {};

            await Promise.all(Object.entries(dependencies).map(async ([name, info]) => {
                if (this.isPotentiallyVulnerable(name)) {
                    const exists = await this.checkNpmPackageExists(name);
                    this.addResult(filePath, 'npm', name, info.version, exists);
                }
            }));
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing package-lock.json: ${error.message}`);
            }
        }
    }

    async scanYarnLock(filePath, content) {
        const lines = content.split('\n');
        const packages = new Map(); // To store name -> version

        let currentPackage = null;
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.endsWith(':') && trimmed.startsWith('"')) {
                // New package entry like "@scope/package@version":
                currentPackage = trimmed.slice(1, -2).split('@')[0]; // Extract name
            } else if (trimmed.startsWith('version ')) {
                if (currentPackage) {
                    const version = trimmed.split(' ')[1].replace(/"/g, '');
                    packages.set(currentPackage, version);
                }
            }
        }

        await Promise.all(Array.from(packages.entries()).map(async ([packageName, version]) => {
            if (this.isPotentiallyVulnerable(packageName)) {
                const exists = await this.checkNpmPackageExists(packageName);
                this.addResult(filePath, 'npm', packageName, version, exists);
            }
        }));
    }

    async scanRequirementsTxt(filePath, content) {
        const lines = content.split('\n');

        await Promise.all(lines.map(async (line) => {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('-')) {
                let packageName, version = 'unknown';

                const versionMatch = trimmed.match(/^([a-zA-Z0-9\-_\.]+(?:\[[^\]]*\])?)\s*([><=!~]+)\s*([^;,\s]+)/);
                if (versionMatch) {
                    packageName = versionMatch[1].replace(/\[.*\]/, '');
                    version = `${versionMatch[2]}${versionMatch[3]}`;
                } else {
                    const packageMatch = trimmed.match(/^([a-zA-Z0-9\-_\.]+)/);
                    if (packageMatch) {
                        packageName = packageMatch[1];
                    } else {
                        return;
                    }
                }

                if (packageName && this.isPotentiallyVulnerable(packageName)) {
                    const exists = await this.checkPyPiPackageExists(packageName);
                    this.addResult(filePath, 'pypi', packageName, version, exists);
                }
            }
        }));
    }

    async scanPyprojectToml(filePath, content) {
        const lines = content.split('\n');
        let inDependencies = false;
        let inOptionalDependencies = false;
        let inPoetryDependencies = false;

        const promises = [];
        lines.forEach((line) => {
            const trimmed = line.trim();

            // Standard [project.dependencies]
            if (trimmed === 'dependencies = [' || trimmed.startsWith('dependencies = [')) {
                inDependencies = true;
                inPoetryDependencies = false;
            } else if (trimmed.includes('optional-dependencies') && trimmed.includes('[')) {
                inOptionalDependencies = true;
                inDependencies = false;
            } else if (trimmed === ']') {
                inDependencies = false;
                inOptionalDependencies = false;
            }

            // Poetry [tool.poetry.dependencies]
            if (trimmed === '[tool.poetry.dependencies]') {
                inPoetryDependencies = true;
                inDependencies = false;
            } else if (trimmed.startsWith('[') && inPoetryDependencies) {
                inPoetryDependencies = false;
            }

            // Parse standard dependencies
            if ((inDependencies || inOptionalDependencies) && trimmed.includes('"')) {
                let packageName, version = 'unknown';

                const depWithVersionMatch = trimmed.match(/"([a-zA-Z0-9\-_\.]+)(?:\[[^\]]*\])?\s*([><=!~]+)\s*([^"]+)"/);
                if (depWithVersionMatch) {
                    packageName = depWithVersionMatch[1];
                    version = `${depWithVersionMatch[2]}${depWithVersionMatch[3]}`;
                } else {
                    const depMatch = trimmed.match(/"([a-zA-Z0-9\-_\.]+)(?:\[[^\]]*\])?"/);
                    if (depMatch) {
                        packageName = depMatch[1];
                    }
                }

                if (packageName && this.isPotentiallyVulnerable(packageName)) {
                    promises.push(this.checkPyPiPackageExists(packageName).then(exists => {
                        this.addResult(filePath, 'pypi', packageName, version, exists);
                    }));
                }
            }

            // Parse Poetry dependencies
            if (inPoetryDependencies && trimmed.includes('=')) {
                const match = trimmed.match(/^([a-zA-Z0-9\-_\.]+)\s*=\s*(.+)/);
                if (match) {
                    const packageName = match[1];
                    let version = match[2].trim().replace(/["']/g, '');
                    if (version.startsWith('{')) {
                        // Handle { version = "^1.0" }
                        const versionMatch = version.match(/version\s*=\s*["']([^"']+)["']/);
                        if (versionMatch) version = versionMatch[1];
                    }
                    if (this.isPotentiallyVulnerable(packageName)) {
                        promises.push(this.checkPyPiPackageExists(packageName).then(exists => {
                            this.addResult(filePath, 'pypi', packageName, version, exists);
                        }));
                    }
                }
            }

            // Handle single-line dependencies
            if (trimmed.startsWith('dependencies') && trimmed.includes('=') && trimmed.includes('[')) {
                const depsMatch = trimmed.match(/dependencies\s*=\s*\[(.*)\]/);
                if (depsMatch) {
                    const depsString = depsMatch[1];
                    const deps = depsString.split(',');

                    deps.forEach(dep => {
                        const cleanDep = dep.trim().replace(/['"]/g, '');
                        let packageName, version = 'unknown';

                        const versionMatch = cleanDep.match(/^([a-zA-Z0-9\-_\.]+)(?:\[[^\]]*\])?\s*([><=!~]+)\s*(.+)/);
                        if (versionMatch) {
                            packageName = versionMatch[1];
                            version = `${versionMatch[2]}${versionMatch[3]}`;
                        } else {
                            const packageMatch = cleanDep.match(/^([a-zA-Z0-9\-_\.]+)/);
                            if (packageMatch) {
                                packageName = packageMatch[1];
                            }
                        }

                        if (packageName && this.isPotentiallyVulnerable(packageName)) {
                            promises.push(this.checkPyPiPackageExists(packageName).then(exists => {
                                this.addResult(filePath, 'pypi', packageName, version, exists);
                            }));
                        }
                    });
                }
            }
        });
        await Promise.all(promises);
    }

    async scanSbom(filePath, content) {
        try {
            const sbomData = JSON.parse(content);

            if (sbomData.bomFormat === 'CycloneDX' || sbomData.components) {
                await this.scanCycloneDx(filePath, sbomData);
            } else if (sbomData.spdxVersion || sbomData.packages) {
                await this.scanSpdx(filePath, sbomData);
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing SBOM file: ${error.message}`);
            }
        }
    }

    async scanCycloneDx(filePath, sbomData) {
        const components = sbomData.components || [];

        await Promise.all(components.map(async (component) => {
            if (component.name && component.type === 'library') {
                const packageName = component.name;
                const version = component.version || 'unknown';
                const ecosystem = this.detectEcosystemFromPurl(component.purl) || 'unknown';

                if (this.isPotentiallyVulnerable(packageName)) {
                    const exists = await this.checkPackageExistsByEcosystem(ecosystem, packageName);
                    this.addResult(filePath, ecosystem, packageName, version, exists);
                }
            }
        }));
    }

    async scanSpdx(filePath, sbomData) {
        const packages = sbomData.packages || [];

        await Promise.all(packages.map(async (pkg) => {
            if (pkg.name && pkg.name !== sbomData.name) {
                const packageName = pkg.name;
                const version = pkg.versionInfo || 'unknown';
                const ecosystem = this.detectEcosystemFromSpdx(pkg) || 'unknown';

                if (this.isPotentiallyVulnerable(packageName)) {
                    const exists = await this.checkPackageExistsByEcosystem(ecosystem, packageName);
                    this.addResult(filePath, ecosystem, packageName, version, exists);
                }
            }
        }));
    }

    async scanSbomXml(filePath, content) {
        const componentRegex = /<component[^>]*type="library"[^>]*>[\s\S]*?<name>([^<]+)<\/name>[\s\S]*?(?:<version>([^<]+)<\/version>)?[\s\S]*?(?:<purl>([^<]+)<\/purl>)?[\s\S]*?<\/component>/g;
        let match;

        const promises = [];
        while ((match = componentRegex.exec(content)) !== null) {
            const packageName = match[1];
            const version = match[2] || 'unknown';
            const purl = match[3];
            const ecosystem = this.detectEcosystemFromPurl(purl) || 'unknown';

            if (this.isPotentiallyVulnerable(packageName)) {
                promises.push(this.checkPackageExistsByEcosystem(ecosystem, packageName).then(exists => {
                    this.addResult(filePath, ecosystem, packageName, version, exists);
                }));
            }
        }
        await Promise.all(promises);
    }

    detectEcosystemFromPurl(purl) {
        if (!purl) return null;

        if (purl.startsWith('pkg:npm/')) return 'npm';
        if (purl.startsWith('pkg:pypi/')) return 'pypi';
        if (purl.startsWith('pkg:cargo/')) return 'cargo';
        if (purl.startsWith('pkg:composer/')) return 'packagist';
        if (purl.startsWith('pkg:gem/')) return 'gem';
        if (purl.startsWith('pkg:maven/')) return 'maven';
        if (purl.startsWith('pkg:golang/')) return 'go';

        return null;
    }

    detectEcosystemFromSpdx(pkg) {
        const downloadLocation = pkg.downloadLocation || '';
        const packageFileName = pkg.packageFileName || '';

        if (downloadLocation.includes('npmjs.org') || packageFileName.includes('.tgz')) return 'npm';
        if (downloadLocation.includes('pypi.org') || downloadLocation.includes('files.pythonhosted.org')) return 'pypi';
        if (downloadLocation.includes('crates.io')) return 'cargo';
        if (downloadLocation.includes('packagist.org')) return 'packagist';
        if (downloadLocation.includes('rubygems.org')) return 'gem';
        if (downloadLocation.includes('maven') || packageFileName.includes('.jar')) return 'maven';
        if (downloadLocation.includes('proxy.golang.org') || downloadLocation.includes('pkg.go.dev')) return 'go';

        return null;
    }

    async scanGoMod(filePath, content) {
        const lines = content.split('\n');

        await Promise.all(lines.map(async (line) => {
            const trimmed = line.trim();
            const requireMatch = trimmed.match(/^\s*([^\s]+)\s+v(.*)$/);

            if (requireMatch) {
                const moduleName = requireMatch[1];
                const version = requireMatch[2] || 'unknown';
                if (this.isPotentiallyVulnerable(moduleName)) {
                    const exists = await this.checkGoPackageExists(moduleName);
                    this.addResult(filePath, 'go', moduleName, version, exists);
                }
            }
        }));
    }

    async scanGoSum(filePath, content) {
        const lines = content.split('\n');
        const modules = new Map(); // name -> version

        lines.forEach(line => {
            const parts = line.split(' ');
            if (parts.length >= 2) {
                const modulePath = parts[0];
                const version = parts[1] || 'unknown';
                if (this.isPotentiallyVulnerable(modulePath)) {
                    if (!modules.has(modulePath)) {
                        modules.set(modulePath, version);
                    }
                }
            }
        });

        await Promise.all(Array.from(modules.entries()).map(async ([moduleName, version]) => {
            const exists = await this.checkGoPackageExists(moduleName);
            this.addResult(filePath, 'go', moduleName, version, exists);
        }));
    }

    async scanCargoToml(filePath, content) {
        const lines = content.split('\n');
        let inDependencies = false;

        const promises = [];
        lines.forEach(line => {
            const trimmed = line.trim();

            if (trimmed === '[dependencies]' || trimmed === '[dev-dependencies]') {
                inDependencies = true;
                return;
            }

            if (trimmed.startsWith('[') && inDependencies) {
                inDependencies = false;
                return;
            }

            if (inDependencies && trimmed.includes('=')) {
                const match = trimmed.match(/^([a-zA-Z0-9\-_]+)\s*=\s*(.+)/);
                if (match) {
                    const packageName = match[1];
                    let version = match[2].trim().replace(/["']/g, '');
                    if (version.startsWith('{')) {
                        const versionMatch = version.match(/version\s*=\s*["']([^"']+)["']/);
                        if (versionMatch) version = versionMatch[1];
                    }
                    if (this.isPotentiallyVulnerable(packageName)) {
                        promises.push(this.checkCratesIoPackageExists(packageName).then(exists => {
                            this.addResult(filePath, 'crates.io', packageName, version, exists);
                        }));
                    }
                }
            }
        });
        await Promise.all(promises);
    }

    async scanComposerJson(filePath, content) {
        try {
            const composerData = JSON.parse(content);
            const dependencies = {
                ...composerData.require,
                ...composerData['require-dev']
            };

            await Promise.all(Object.entries(dependencies || {}).map(async ([name, version]) => {
                if (name !== 'php' && this.isPotentiallyVulnerable(name)) {
                    const exists = await this.checkPackagistPackageExists(name);
                    this.addResult(filePath, 'packagist', name, version, exists);
                }
            }));
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing composer.json: ${error.message}`);
            }
        }
    }

    async scanGemfile(filePath, content) {
        const lines = content.split('\n');

        await Promise.all(lines.map(async (line) => {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) return;

            let gemMatch, version = 'unknown';

            // gem 'name', 'version', github: 'repo' - skip if git/source
            if (trimmed.includes('git') || trimmed.includes('path')) return;

            gemMatch = trimmed.match(/gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/);
            if (gemMatch) {
                const packageName = gemMatch[1];
                version = gemMatch[2];
                if (this.isPotentiallyVulnerable(packageName)) {
                    const exists = await this.checkRubyGemsPackageExists(packageName);
                    this.addResult(filePath, 'rubygems', packageName, version, exists);
                }
                return;
            }

            gemMatch = trimmed.match(/gem\s+['"]([^'"]+)['"]\s*,\s*version:\s*['"]([^'"]+)['"]/);
            if (gemMatch) {
                const packageName = gemMatch[1];
                version = gemMatch[2];
                if (this.isPotentiallyVulnerable(packageName)) {
                    const exists = await this.checkRubyGemsPackageExists(packageName);
                    this.addResult(filePath, 'rubygems', packageName, version, exists);
                }
                return;
            }

            gemMatch = trimmed.match(/gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"](?:\s*,.*)?/);
            if (gemMatch) {
                const packageName = gemMatch[1];
                version = gemMatch[2];
                if (this.isPotentiallyVulnerable(packageName)) {
                    const exists = await this.checkRubyGemsPackageExists(packageName);
                    this.addResult(filePath, 'rubygems', packageName, version, exists);
                }
                return;
            }

            gemMatch = trimmed.match(/gem\s+['"]([^'"]+)['"](?:\s*$|\s*,\s*(?!['"]))/);
            if (gemMatch && this.isPotentiallyVulnerable(gemMatch[1])) {
                const exists = await this.checkRubyGemsPackageExists(gemMatch[1]);
                this.addResult(filePath, 'rubygems', gemMatch[1], 'unknown', exists);
            }
        }));
    }

    async scanPomXml(filePath, content) {
        const dependencyBlocks = content.match(/<dependency[^>]*>[\s\S]*?<\/dependency>/g) || [];

        await Promise.all(dependencyBlocks.map(async (block) => {
            const groupIdMatch = block.match(/<groupId>([^<]+)<\/groupId>/);
            const artifactIdMatch = block.match(/<artifactId>([^<]+)<\/artifactId>/);
            const versionMatch = block.match(/<version>([^<]+)<\/version>/);

            if (groupIdMatch && artifactIdMatch) {
                const groupId = groupIdMatch[1].trim();
                const artifactId = artifactIdMatch[1].trim();
                const version = versionMatch ? versionMatch[1].trim() : 'unknown';
                const fullName = `${groupId}:${artifactId}`;

                if (this.isPotentiallyVulnerable(fullName)) {
                    const exists = await this.checkMavenPackageExists(fullName);
                    this.addResult(filePath, 'maven', fullName, version, exists);
                }
            }
        }));
    }

    async scanGradle(filePath, content) {
        const lines = content.split('\n');

        await Promise.all(lines.map(async (line) => {
            const trimmed = line.trim();

            let depMatch, groupId, artifactId, version = 'unknown';

            depMatch = trimmed.match(/(?:implementation|compile|api|testImplementation|runtimeOnly|compileOnly|testCompileOnly|testRuntimeOnly)\s+['"]([^'"]+)['"]/);
            if (depMatch) {
                const parts = depMatch[1].split(':');
                if (parts.length >= 2) {
                    groupId = parts[0];
                    artifactId = parts[1];
                    version = parts[2] || 'unknown';
                    const fullName = `${groupId}:${artifactId}`;
                    if (this.isPotentiallyVulnerable(fullName)) {
                        const exists = await this.checkMavenPackageExists(fullName);
                        this.addResult(filePath, 'maven', fullName, version, exists);
                    }
                }
                return;
            }

            const mapMatch = trimmed.match(/(?:implementation|compile|api|testImplementation|runtimeOnly|compileOnly|testCompileOnly|testRuntimeOnly)\s+group:\s*['"]([^'"]+)['"],?\s*name:\s*['"]([^'"]+)['"](?:,?\s*version:\s*['"]([^'"]+)['"])?/);
            if (mapMatch) {
                groupId = mapMatch[1];
                artifactId = mapMatch[2];
                version = mapMatch[3] || 'unknown';
                const fullName = `${groupId}:${artifactId}`;
                if (this.isPotentiallyVulnerable(fullName)) {
                    const exists = await this.checkMavenPackageExists(fullName);
                    this.addResult(filePath, 'maven', fullName, version, exists);
                }
                return;
            }

            const altMapMatch = trimmed.match(/(?:implementation|compile|api|testImplementation|runtimeOnly|compileOnly|testCompileOnly|testRuntimeOnly)\s+name:\s*['"]([^'"]+)['"],?\s*group:\s*['"]([^'"]+)['"](?:,?\s*version:\s*['"]([^'"]+)['"])?/);
            if (altMapMatch) {
                artifactId = altMapMatch[1];
                groupId = altMapMatch[2];
                version = altMapMatch[3] || 'unknown';
                const fullName = `${groupId}:${artifactId}`;
                if (this.isPotentiallyVulnerable(fullName)) {
                    const exists = await this.checkMavenPackageExists(fullName);
                    this.addResult(filePath, 'maven', fullName, version, exists);
                }
            }
        }));
    }

    isPotentiallyVulnerable(packageName) {
        if (packageName.includes('://') || packageName.startsWith('git+') || packageName.includes('github:') || packageName.includes('path:')) {
            return false;
        }

        const wellKnownPackages = [
            'react', 'vue', 'angular', 'lodash', 'express', 'axios', 'moment', 'jquery', 'bootstrap',
            'webpack', 'babel', 'eslint', 'jest', 'mocha', 'typescript', 'commander', 'chalk', 'inquirer',
            'yargs', 'fs-extra', 'rimraf', 'glob', 'mkdirp', 'debug', 'semver', 'uuid', 'cors', 'dotenv',
            'nodemon', 'concurrently', 'cross-env', 'husky', 'lint-staged', 'requests', 'flask', 'django',
            'numpy', 'pandas', 'matplotlib', 'scipy', 'tensorflow', 'pytorch', 'serde', 'tokio', 'actix',
            'rails', 'sqlite3', 'pg', 'mysql2', 'puma', 'sidekiq', 'devise', 'rspec', 'spring-boot-starter',
            'hibernate', 'junit', 'gson', 'log4j'
        ];

        if (wellKnownPackages.includes(packageName.toLowerCase())) {
            return false;
        }

        if (packageName.startsWith('@')) {
            // Special patterns for scoped packages
            const scopedSuspiciousPatterns = [
                /^@[a-z0-9]+\/[a-z0-9]{3,10}$/i,
                /^@[a-z0-9]+\/(lib|utils?|helper|common|core|base|tools?|sdk|internal|private)$/i,
                /^@[a-z0-9]+\/(test|demo|example|sample|internal|private)[-_]?/i,
                /^@[a-z0-9]+\/[a-z0-9]*[-_]?(test|demo|example|sample|internal|private)$/i,
                /^@[0-9]+[a-z]+\/[a-z0-9]*$/i,
                /^@[a-z0-9]+\/[-_]internal[-_]/i,
                /^@[a-z0-9]+\/[-_]private[-_]/i
            ];
            return scopedSuspiciousPatterns.some(pattern => pattern.test(packageName)) || packageName.length <= 10;
        }

        // General patterns for non-scoped
        const suspiciousPatterns = [
            /^[a-z0-9]+[-_][a-z0-9]+$/i,
            /^[a-z0-9]{3,10}$/i,
            /^(lib|utils?|helper|common|core|base|tools?|sdk|internal|private)$/i,
            /^(test|demo|example|sample|internal|private)[-_]?/i,
            /^[a-z0-9]*[-_]?(test|demo|example|sample|internal|private)$/i,
            /^[0-9]+[a-z]+[-_]?[a-z0-9]*$/i,
            /[-_]internal[-_]/i,
            /[-_]private[-_]/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(packageName)) || packageName.length <= 4;
    }

    async checkPackageExistsByEcosystem(ecosystem, packageName) {
        switch (ecosystem) {
            case 'npm':
                return this.checkNpmPackageExists(packageName);
            case 'pypi':
                return this.checkPyPiPackageExists(packageName);
            case 'cargo':
                return this.checkCratesIoPackageExists(packageName);
            case 'packagist':
                return this.checkPackagistPackageExists(packageName);
            case 'gem':
                return this.checkRubyGemsPackageExists(packageName);
            case 'maven':
                return this.checkMavenPackageExists(packageName);
            case 'go':
                return this.checkGoPackageExists(packageName);
            default:
                return 'unknown';
        }
    }

    async checkNpmPackageExists(packageName) {
        // No encoding for @ or /; they are valid in path
        try {
            await this.makeHttpRequest(`https://registry.npmjs.org/${packageName}`);
            return true;
        } catch {
            return false;
        }
    }

    async checkPyPiPackageExists(packageName) {
        try {
            await this.makeHttpRequest(`https://pypi.org/pypi/${packageName}/json`);
            return true;
        } catch {
            return false;
        }
    }

    async checkCratesIoPackageExists(packageName) {
        try {
            await this.makeHttpRequest(`https://crates.io/api/v1/crates/${packageName}`);
            return true;
        } catch {
            return false;
        }
    }

    async checkPackagistPackageExists(packageName) {
        try {
            await this.makeHttpRequest(`https://packagist.org/packages/${packageName}.json`);
            return true;
        } catch {
            return false;
        }
    }

    async checkRubyGemsPackageExists(packageName) {
        const cleanPackageName = packageName.replace(/[<>=!~\s]/g, '').split(',')[0].trim();
        try {
            await this.makeHttpRequest(`https://rubygems.org/api/v1/gems/${cleanPackageName}.json`);
            return true;
        } catch {
            try {
                await this.makeHttpRequest(`https://rubygems.org/api/v1/versions/${cleanPackageName}.json`);
                return true;
            } catch {
                return false;
            }
        }
    }

    async checkMavenPackageExists(packageName) {
        let groupId, artifactId;
        if (packageName.includes(':')) {
            [groupId, artifactId] = packageName.split(':');
        } else {
            return 'unknown';
        }

        const groupPath = groupId.replace(/\./g, '/');
        const metadataUrl = `https://repo1.maven.org/maven2/${groupPath}/${artifactId}/maven-metadata.xml`;

        try {
            await this.makeHttpRequest(metadataUrl);
            return true;
        } catch {
            return false;
        }
    }

    async checkGoPackageExists(moduleName) {
        try {
            const response = await this.makeHttpRequest(`https://proxy.golang.org/${moduleName}/@v/list`);
            let data = '';
            response.on('data', chunk => { data += chunk; });
            await new Promise(resolve => response.on('end', resolve));
            return data.trim() !== '';
        } catch {
            return false;
        }
    }

    makeHttpRequest(url) {
        const parsedUrl = urlModule.parse(url);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;

        return new Promise((resolve, reject) => {
            const request = protocol.get(url, {
                timeout: this.timeout,
                headers: { 'User-Agent': this.userAgent }
            }, (response) => {
                if (response.statusCode === 200) {
                    resolve(response);
                } else {
                    reject(new Error(`Status: ${response.statusCode}`));
                }
            });

            request.on('error', reject);
            request.on('timeout', () => {
                request.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    addResult(filePath, ecosystem, packageName, version, exists) {
        const risk = exists === false ? 'HIGH' : exists === true ? 'LOW' : 'UNKNOWN';

        this.results.push({
            file: filePath,
            ecosystem,
            package: packageName,
            version,
            exists,
            risk
        });
    }

    printResults() {
        if (this.jsonMode) {
            const vulnerabilities = this.results
                .filter(r => r.risk === 'HIGH' || r.risk === 'UNKNOWN')
                .map(result => ({
                    package: result.package,
                    version: result.version,
                    ecosystem: result.ecosystem,
                    file: result.file
                }));

            if (vulnerabilities.length > 0) {
                const output = {
                    "name": "super-confused",
                    "description": "Identify dependency confusion in your source code",
                    "author": "6mile",
                    "dependency-confused-packages": vulnerabilities
                };
                console.log(JSON.stringify(output, null, 2));
            }
            return;
        }

        const vulnerabilities = this.results.filter(r => r.risk === 'HIGH' || r.risk === 'UNKNOWN');

        if (vulnerabilities.length === 0) {
            console.log('No Dependency Confusion Opportunities found.');
            return;
        }

        vulnerabilities.forEach(result => {
            console.log('');
            console.log('DEPENDENCY CONFUSION OPPORTUNITY!');
            console.log(`${result.package} (${result.ecosystem}) in ${result.file}`);
            console.log(`Version: ${result.version}`);
            console.log(`Risk: ${result.risk}`);
        });
    }
}

async function main() {
    const args = process.argv.slice(2);
    let jsonMode = false;
    let targetPath;

    if (args.includes('--json')) {
        jsonMode = true;
        targetPath = args.find(arg => arg !== '--json');
    } else {
        targetPath = args[0];
    }

    if (!targetPath) {
        console.log('Usage: super-confused [--json] <path|url>');
        console.log('');
        console.log('Examples:');
        console.log('  super-confused ./package.json');
        console.log('  super-confused --json ./my-project');
        console.log('  super-confused https://github.com/user/repo/blob/main/package.json');
        console.log('  super-confused .');
        process.exit(1);
    }

    if (!targetPath.startsWith('http') && !fs.existsSync(targetPath)) {
        if (!jsonMode) {
            console.error(`Path does not exist: ${targetPath}`);
        }
        process.exit(1);
    }

    const scanner = new SuperConfused(jsonMode);

    try {
        await scanner.scan(targetPath);
    } catch (error) {
        if (!jsonMode) {
            console.error(`Scan failed: ${error.message}`);
        }
        process.exit(1);
    }
}

module.exports = SuperConfused;

if (require.main === module) {
    main().catch(console.error);
}