#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

# DKapture Source Package Generator
# Generates source tarball (tar.gz) and dkapture.spec for CI RPM builds
#
# Usage:
#   ./script/gen-source-pkg.sh [--headers <dir>]
#
# Options:
#   --headers <dir>     Pre-built BPF headers directory, must contain:
#                       vmlinux_x86_64.h,  vmlinux_aarch64.h,  vmlinux_loongarch64.h,
#                       kconfig_x86_64.h,  kconfig_aarch64.h,  kconfig_loongarch64.h.
#                       All placed at bpf/build/include/
#
# Output:
#   dkapture-<version>.tar.gz    -- source tarball
#   dkapture.spec                -- RPM spec file

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_NAME="dkapture"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HEADERS_DIR=""

# Parse command-line options
while [ $# -gt 0 ]; do
    case "$1" in
        --headers)
            HEADERS_DIR="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [--headers <dir>]"
            exit 1
            ;; 
    esac
done

# Resolve relative paths before any cd
if [ -n "${HEADERS_DIR}" ]; then
    HEADERS_DIR="$(realpath "${HEADERS_DIR}")"
fi

# Determine version and release from git
GIT_DESC=$(git -C "${PROJECT_ROOT}" describe --tags --long 2>/dev/null || echo "v1.0.0-0-g0000000")

# Parse: git describe --tags --long → v1.0.2-5-gabcdef1
#   v1.0.2 = tag, 5 = commits since tag, gabcdef1 = abbreviated hash
TAG_VER=$(echo "${GIT_DESC}" | sed 's/^v//' | sed 's/-[0-9]*-g.*//')
COMMIT_DIST=$(echo "${GIT_DESC}" | sed 's/.*-\([0-9]*\)-g.*/\1/')

RPM_VERSION=$(echo "${TAG_VER}" | sed 's/-.*//g' | sed 's/+.*//g')
RPM_RELEASE=$((COMMIT_DIST + 1))

# Find previous version tag for changelog
PREV_TAG=$(git -C "${PROJECT_ROOT}" tag -l 'v*' --sort=-version:refname 2>/dev/null | grep -A1 "^v${TAG_VER}$" | tail -1)
if [ -z "$PREV_TAG" ] || [ "$PREV_TAG" = "v${TAG_VER}" ]; then
    CHANGELOG_LOG="- Initial release"
else
    CHANGELOG_LOG=$(git -C "${PROJECT_ROOT}" log --format='- %s' "${PREV_TAG}..HEAD" 2>/dev/null)
fi

PACKAGE_DIR="${PROJECT_NAME}-${RPM_VERSION}"
TARBALL="${PROJECT_NAME}-${RPM_VERSION}.tar.gz"
SPEC_FILE="${PROJECT_NAME}.spec"

WORK_DIR=$(mktemp -d /tmp/dkapture-srcpkg-XXXXXX)
trap "rm -rf ${WORK_DIR}" EXIT

# ============================================================
# Step 1: Create source tarball
# ============================================================
echo -e "${BLUE}Creating source tarball...${NC}"

PACKAGE_ROOT="${WORK_DIR}/${PACKAGE_DIR}"
mkdir -p "${PACKAGE_ROOT}"

# Collect main repo tracked files, excluding submodules and unneeded dirs
echo -e "${YELLOW}Collecting main repo source files...${NC}"
cd "${PROJECT_ROOT}"
git ls-files --cached | while IFS= read -r f; do
    case "$f" in
        bpf|bpf/*|googletest|googletest/*|test/*|tools/*|.gitmodules|*.spec)
            # bpf/ handled separately; googletest/test/tools not needed for RPM
            continue
            ;;
        *)
            dest="${PACKAGE_ROOT}/${f}"
            mkdir -p "$(dirname "$dest")"
            cp -a "$f" "$dest"
            ;;
    esac
done

# Collect bpf submodule content
if [ -d "${PROJECT_ROOT}/bpf" ]; then
    echo -e "${YELLOW}Collecting bpf submodule source files...${NC}"
    cd "${PROJECT_ROOT}/bpf"
    git ls-files --recurse-submodules --cached 2>/dev/null | while IFS= read -r f; do
        dest="${PACKAGE_ROOT}/bpf/${f}"
        mkdir -p "$(dirname "$dest")"
        cp -a "$f" "$dest"
    done
fi

# Remove any empty bpf directory gitlink placeholder
find "${PACKAGE_ROOT}/bpf" -maxdepth 0 -empty -exec rmdir {} \; 2>/dev/null || true

# Include pre-built BPF headers if specified
if [ -n "${HEADERS_DIR}" ]; then
    if [ ! -d "${HEADERS_DIR}" ]; then
        echo -e "${RED}Error: headers directory not found at ${HEADERS_DIR}${NC}"
        exit 1
    fi

    # Required files
    HEADER_FILES=(\
        "vmlinux_x86_64.h" "vmlinux_aarch64.h" "vmlinux_loongarch64.h" \
        "kconfig_x86_64.h" "kconfig_aarch64.h" "kconfig_loongarch64.h")
    for f in "${HEADER_FILES[@]}"; do
        if [ ! -f "${HEADERS_DIR}/${f}" ]; then
            echo -e "${RED}Error: required file '${f}' not found in ${HEADERS_DIR}${NC}"
            exit 1
        fi
    done

    HEADERS_DEST="${PACKAGE_ROOT}/bpf/build/include"
    mkdir -p "${HEADERS_DEST}"
    for f in "${HEADER_FILES[@]}"; do
        cp "${HEADERS_DIR}/${f}" "${HEADERS_DEST}/${f}"
    done
    echo -e "${GREEN}Pre-built BPF headers included in source tarball${NC}"
fi

echo -e "${YELLOW}Creating tarball: ${TARBALL}${NC}"
cd "${WORK_DIR}"
tar czf "${TARBALL}" "${PACKAGE_DIR}"
mv "${TARBALL}" "${PROJECT_ROOT}/"
echo -e "${GREEN}Source tarball created: ${PROJECT_ROOT}/${TARBALL}${NC}"

# ============================================================
# Step 2: Generate dkapture.spec
# ============================================================
echo -e "${BLUE}Generating ${SPEC_FILE}...${NC}"

cat > "${PROJECT_ROOT}/${SPEC_FILE}" << SPECEOF
Name:           ${PROJECT_NAME}
Version:        ${RPM_VERSION}
Release:        ${RPM_RELEASE}%{?dist}
Summary:        Deepin Kernel Capture - eBPF-based system observation tools

License:        LGPL-2.1
URL:            https://github.com/DKapture
Source0:        %{name}-%{version}.tar.gz
ExclusiveArch:  x86_64 aarch64 loongarch64

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  clang
BuildRequires:  bpftool
BuildRequires:  libbpf-devel >= 1.0
BuildRequires:  python3
BuildRequires:  make
BuildRequires:  kernel-devel

Requires:       libbpf >= 1.0
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
DKapture is a user-space toolset and dynamic library for observing
and manipulating kernel data objects or behaviors. It is based on
Linux kernel's emerging eBPF technology, which is safer than
kernel module-based technologies like sysdig and systemtap.

Features include:
- Network information collection
- File system information collection
- Process information collection
- IO information collection
- System call information collection
- Scheduling information collection
- Interrupt information collection
- Memory information collection

%prep
%setup -q -n %{name}-%{version}

%build
# Determine build architecture
case \$(uname -m) in
    x86_64)      KARCH=x86_64 ;;
    aarch64)     KARCH=aarch64 ;;
    loongarch64) KARCH=loongarch64 ;;
    *)           KARCH="" ;;
esac

# Set up pre-built headers for the build architecture
if [ -n "\${KARCH}" ]; then
    [ -f bpf/build/include/kconfig_\${KARCH}.h ] && \\
        cp bpf/build/include/kconfig_\${KARCH}.h bpf/build/include/kconfig.h
    [ -f bpf/build/include/vmlinux_\${KARCH}.h ] && \\
        cp bpf/build/include/vmlinux_\${KARCH}.h bpf/build/include/vmlinux.h
fi

# Discover actual kernel-devel include path (uname -r may differ in chroot)
KHEADERS_DIR=\$(ls -d /lib/modules/*/build/include 2>/dev/null | head -1)
if [ -z "\${KHEADERS_DIR}" ]; then
    KHEADERS_DIR=/lib/modules/\$(uname -r)/build/include
fi

# If pre-built vmlinux.h exists, make self-referential dependency to prevent rebuild
VMLINUX_OVERRIDE=""
if [ -f bpf/build/include/vmlinux.h ]; then
    VMLINUX_OVERRIDE="VMLINUX=bpf/build/include/vmlinux.h"
fi

make %{?_smp_mflags} USE_SUBMODULE=0                     \\
    \${VMLINUX_OVERRIDE}                                   \\
    KHEADERS_DIR="\${KHEADERS_DIR}"                       \\
    bpf                                                  \\
    observe BPF_DIR_PATCH=/usr/lib/dkapture               \\
    filter BPF_DIR_PATCH=/usr/lib/dkapture                \\
    policy BPF_DIR_PATCH=/usr/lib/dkapture                \\
    so                                                    \\
    demo

%install
# Directories
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib
mkdir -p %{buildroot}/usr/lib/dkapture
mkdir -p %{buildroot}/usr/include/%{name}
mkdir -p %{buildroot}/etc/dkapture/policy

# Executables from observe
for b in build/observe/*; do
    [ -f "\$b" ] && [ -x "\$b" ] && cp "\$b" "%{buildroot}/usr/bin/dk-\$(basename \$b)"
done

# Executables from filter
for b in build/filter/*; do
    [ -f "\$b" ] && [ -x "\$b" ] && cp "\$b" "%{buildroot}/usr/bin/dk-\$(basename \$b)"
done

# Executables from policy
for b in build/policy/*; do
    [ -f "\$b" ] && [ -x "\$b" ] && cp "\$b" "%{buildroot}/usr/bin/dk-\$(basename \$b)"
done

# Demo executable
if [ -f build/demo/demo ]; then
    cp build/demo/demo %{buildroot}/usr/bin/dk-demo
fi

# Dynamic library
if [ -f build/so/libdkapture.so ]; then
    cp build/so/libdkapture.so %{buildroot}/usr/lib/libdkapture.so
fi

# BPF object files
for d in filter observe policy; do
    if [ -d bpf/build/\$d ]; then
        cp bpf/build/\$d/*.bpf.o %{buildroot}/usr/lib/dkapture/ 2>/dev/null || true
    fi
done

# Header files
if [ -f bpf/export/dkapture.h ]; then
    cp bpf/export/dkapture.h %{buildroot}/usr/include/%{name}/dkapture.h
fi

# Policy files
cp policy/elfverify.pol %{buildroot}/etc/dkapture/policy/elfverify.pol
cp policy/frtp.pol %{buildroot}/etc/dkapture/policy/frtp.pol

%files
%attr(755,root,root) /usr/bin/dk-*
%attr(755,root,root) /usr/lib/libdkapture.so
%attr(644,root,root) /usr/lib/dkapture/*.bpf.o
%attr(644,root,root) /usr/include/%{name}/dkapture.h
%attr(644,root,root) /etc/dkapture/policy/elfverify.pol
%attr(644,root,root) /etc/dkapture/policy/frtp.pol

%post
/sbin/ldconfig
echo "DKapture installation completed successfully!"

%postun
/sbin/ldconfig
echo "DKapture uninstallation completed successfully!"

%changelog
* $(LC_ALL=C date +"%a %b %d %Y") DKapture Team - ${RPM_VERSION}-${RPM_RELEASE}
${CHANGELOG_LOG}
SPECEOF

echo -e "${GREEN}Spec file created: ${PROJECT_ROOT}/${SPEC_FILE}${NC}"

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN} Source package generation complete!${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo -e "  ${YELLOW}Tarball:${NC} ${TARBALL}"
echo -e "  ${YELLOW}Spec:${NC}    ${SPEC_FILE}"
echo ""
echo -e "${YELLOW}CI build instructions:${NC}"
echo ""
echo -e "  # Copy files to RPM build tree"
echo -e "  cp ${TARBALL} ~/rpmbuild/SOURCES/"
echo -e "  cp ${SPEC_FILE} ~/rpmbuild/SPECS/"
echo ""
echo -e "  # Build binary RPM from source"
echo -e "  rpmbuild -ba ~/rpmbuild/SPECS/${SPEC_FILE}"
echo ""
echo -e "  # Or build binary RPM directly"
echo -e "  rpmbuild -bb ~/rpmbuild/SPECS/${SPEC_FILE}"
echo ""
echo -e "  # Or rebuild from source RPM"
echo -e "  rpmbuild -ra ~/rpmbuild/SRPMS/${PROJECT_NAME}-${RPM_VERSION}-${RPM_RELEASE}*.src.rpm"
echo ""
