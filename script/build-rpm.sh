#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

# DKapture RPM Package Builder
# RPM packaging script that meets pack-rule.txt requirements

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project information
PROJECT_NAME="dkapture"

: ${IN_KERNEL_TREE:=0}

if [ "$IN_KERNEL_TREE" = 1 ]; then
    VERSION=$(tail -n1 version 2>/dev/null | sed 's/^v//' || echo "1.0.0")
    USE_SUBMODULE=0
else
    VERSION=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "1.0.0")
    USE_SUBMODULE=1
fi

# Extract major.minor.patch from version for RPM
RPM_VERSION=$(echo "${VERSION}" | sed 's/-.*//g' | sed 's/+.*//g')
RPM_RELEASE="1"

ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    RPM_ARCH="aarch64"
elif [ "$ARCH" = "x86_64" ]; then
    RPM_ARCH="x86_64"
else
    RPM_ARCH="$ARCH"
fi

PACKAGE_NAME="${PROJECT_NAME}-${RPM_VERSION}-${RPM_RELEASE}.${RPM_ARCH}"

# Directory definitions
BUILD_DIR="build"
RPM_BUILD_DIR="${BUILD_DIR}/rpm"
INSTALL_DIR="${RPM_BUILD_DIR}/usr"
BIN_DIR="${INSTALL_DIR}/bin"
LIB_DIR="${INSTALL_DIR}/lib"
DKAPTURE_LIB_DIR="${INSTALL_DIR}/lib/dkapture"
INCLUDE_DIR="${INSTALL_DIR}/include"
ETC_DIR="${RPM_BUILD_DIR}/etc"
SPEC_DIR="${BUILD_DIR}/spec"

if [ $(nproc) -gt 1 ]; then
    MAKE="make -j$(($(nproc)-1)) Release=1 USE_SUBMODULE=${USE_SUBMODULE}"
else
    MAKE="make Release=1 USE_SUBMODULE=${USE_SUBMODULE}"
fi

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    make distclean
    rm -rf "${SPEC_DIR}"
}

# Check dependencies function
check_dependencies() {
    echo -e "${BLUE}Checking build dependencies...${NC}"

    local missing_deps=()

    # Check basic tools
    command -v make >/dev/null 2>&1 || missing_deps+=("make")
    command -v rpmbuild >/dev/null 2>&1 || missing_deps+=("rpm-build")
    command -v gcc >/dev/null 2>&1 || missing_deps+=("gcc")
    command -v g++ >/dev/null 2>&1 || missing_deps+=("gcc-c++")
    command -v clang >/dev/null 2>&1 || missing_deps+=("clang")
    command -v bpftool >/dev/null 2>&1 || missing_deps+=("bpftool")

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing the following dependencies:${NC}"
        printf '%s\n' "${missing_deps[@]}"
        echo -e "${YELLOW}Please run: sudo yum install -y rpm-build make gcc gcc-c++ clang bpftool libbpf-devel${NC}"
        echo -e "${YELLOW}Or: sudo dnf install -y rpm-build make gcc gcc-c++ clang bpftool libbpf-devel${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All dependency checks passed${NC}"
}

echo -e "${GREEN}Starting DKapture RPM package build...${NC}"

# Check dependencies
check_dependencies

# Clean previous build
cleanup

# Create directory structure after cleanup
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p "${SPEC_DIR}"
mkdir -p "${RPM_BUILD_DIR}/usr/bin"
mkdir -p "${RPM_BUILD_DIR}/usr/lib"
mkdir -p "${RPM_BUILD_DIR}/usr/lib/dkapture"
mkdir -p "${RPM_BUILD_DIR}/usr/include/${PROJECT_NAME}"
mkdir -p "${RPM_BUILD_DIR}/etc/dkapture/policy"

# Copy policy files - avoid duplicates by checking if already copied
if [[ -f "policy/elfverify.pol" ]]; then
    echo -e "${BLUE}Copying elfverify.pol to /etc/dkapture/policy...${NC}"
    cp "policy/elfverify.pol" "${RPM_BUILD_DIR}/etc/dkapture/policy/elfverify.pol"
elif [[ -f "elfverify.pol" ]]; then
    echo -e "${BLUE}Copying elfverify.pol to /etc/dkapture/policy...${NC}"
    cp "elfverify.pol" "${RPM_BUILD_DIR}/etc/dkapture/policy/elfverify.pol"
fi

if [[ -f "policy/frtp.pol" ]]; then
    echo -e "${BLUE}Copying frtp.pol to /etc/dkapture/policy...${NC}"
    cp "policy/frtp.pol" "${RPM_BUILD_DIR}/etc/dkapture/policy/frtp.pol"
elif [[ -f "frtp.pol" ]]; then
    echo -e "${BLUE}Copying frtp.pol to /etc/dkapture/policy...${NC}"
    cp "frtp.pol" "${RPM_BUILD_DIR}/etc/dkapture/policy/frtp.pol"
fi

# Compile project (excluding googletest, test and tools)
echo -e "${YELLOW}Compiling project...${NC}"
echo -e "${BLUE}Cleaning previous compilation...${NC}"
${MAKE} clean || echo -e "${YELLOW}Warning: Clean failed (may be first compilation)${NC}"

echo -e "${BLUE}Compiling include module...${NC}"
${MAKE} include || { echo -e "${RED}Error: include module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling observe module...${NC}"
${MAKE} observe BPF_DIR_PATCH="${DKAPTURE_LIB_DIR#$RPM_BUILD_DIR}" || { echo -e "${RED}Error: observe module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling filter module...${NC}"
${MAKE} filter BPF_DIR_PATCH="${DKAPTURE_LIB_DIR#$RPM_BUILD_DIR}" || { echo -e "${RED}Error: filter module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling policy module...${NC}"
${MAKE} policy BPF_DIR_PATCH="${DKAPTURE_LIB_DIR#$RPM_BUILD_DIR}" || { echo -e "${RED}Error: policy module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling so module...${NC}"
${MAKE} so || { echo -e "${RED}Error: so module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling demo module...${NC}"
${MAKE} demo || { echo -e "${RED}Error: demo module compilation failed${NC}"; exit 1; }

# Collect binary files to /usr/bin
echo -e "${YELLOW}Collecting binary files to /usr/bin...${NC}"

# Executable files in observe directory
echo -e "${BLUE}Copying executable files from observe directory...${NC}"
for binary in build/observe/*; do
    if [[ -f "$binary" && -x "$binary" ]]; then
        basename_binary=$(basename "$binary")
        new_name="dk-${basename_binary}"
        echo "  Copying: $(basename "$binary") -> ${BIN_DIR}/${new_name}"
        cp "$binary" "${BIN_DIR}/${new_name}"
    fi
done

# Executable files in filter directory
echo -e "${BLUE}Copying executable files from filter directory...${NC}"
for binary in build/filter/*; do
    if [[ -f "$binary" && -x "$binary" ]]; then
        basename_binary=$(basename "$binary")
        new_name="dk-${basename_binary}"
        echo "  Copying: $(basename "$binary") -> ${BIN_DIR}/${new_name}"
        cp "$binary" "${BIN_DIR}/${new_name}"
    fi
done

# Executable files in policy directory
echo -e "${BLUE}Copying executable files from policy directory...${NC}"
for binary in build/policy/*; do
    if [[ -f "$binary" && -x "$binary" ]]; then
        basename_binary=$(basename "$binary")
        new_name="dk-${basename_binary}"
        echo "  Copying: $(basename "$binary") -> ${BIN_DIR}/${new_name}"
        cp "$binary" "${BIN_DIR}/${new_name}"
    fi
done

# Demo executable file
if [[ -f "build/demo/demo" ]]; then
    echo -e "${BLUE}Copying demo program...${NC}"
    echo "  Copying: demo -> ${BIN_DIR}/dk-demo"
    cp "build/demo/demo" "${BIN_DIR}/dk-demo"
fi

# Collect dynamic libraries to /usr/lib
echo -e "${YELLOW}Collecting dynamic libraries to /usr/lib...${NC}"
if [[ -f "build/so/libdkapture.so" ]]; then
    echo "  Copying: libdkapture.so -> ${LIB_DIR}/libdkapture.so"
    cp "build/so/libdkapture.so" "${LIB_DIR}/libdkapture.so"
fi

# Collect BPF object files to /usr/lib/dkapture
echo -e "${YELLOW}Collecting BPF object files to /usr/lib/dkapture...${NC}"

# Copy .bpf.o files from bpf/build/filter directory
echo -e "${BLUE}Copying BPF object files from filter directory...${NC}"
if [[ -d "bpf/build/filter" ]]; then
    for bpf_file in bpf/build/filter/*.bpf.o; do
        if [[ -f "$bpf_file" ]]; then
            basename_bpf=$(basename "$bpf_file")
            echo "  Copying: ${basename_bpf} -> ${DKAPTURE_LIB_DIR}/${basename_bpf}"
            cp "$bpf_file" "${DKAPTURE_LIB_DIR}/${basename_bpf}"
        fi
    done
fi

# Copy .bpf.o files from bpf/build/observe directory
echo -e "${BLUE}Copying BPF object files from observe directory...${NC}"
if [[ -d "bpf/build/observe" ]]; then
    for bpf_file in bpf/build/observe/*.bpf.o; do
        if [[ -f "$bpf_file" ]]; then
            basename_bpf=$(basename "$bpf_file")
            echo "  Copying: ${basename_bpf} -> ${DKAPTURE_LIB_DIR}/${basename_bpf}"
            cp "$bpf_file" "${DKAPTURE_LIB_DIR}/${basename_bpf}"
        fi
    done
fi

# Copy .bpf.o files from bpf/build/policy directory
echo -e "${BLUE}Copying BPF object files from policy directory...${NC}"
if [[ -d "bpf/build/policy" ]]; then
    for bpf_file in bpf/build/policy/*.bpf.o; do
        if [[ -f "$bpf_file" ]]; then
            basename_bpf=$(basename "$bpf_file")
            echo "  Copying: ${basename_bpf} -> ${DKAPTURE_LIB_DIR}/${basename_bpf}"
            cp "$bpf_file" "${DKAPTURE_LIB_DIR}/${basename_bpf}"
        fi
    done
fi

# Collect header files to /usr/include/${PROJECT_NAME}
echo -e "${YELLOW}Collecting header files to /usr/include/${PROJECT_NAME}...${NC}"
if [[ -f "bpf/export/dkapture.h" ]]; then
    echo "  Copying: dkapture.h -> ${INCLUDE_DIR}/${PROJECT_NAME}/dkapture.h"
    cp "bpf/export/dkapture.h" "${INCLUDE_DIR}/${PROJECT_NAME}/dkapture.h"
else
    echo -e "${YELLOW}Warning: bpf/export/dkapture.h not found${NC}"
fi

# Create RPM spec file
echo -e "${YELLOW}Creating RPM spec file...${NC}"
cat > "${SPEC_DIR}/${PROJECT_NAME}.spec" << EOF
Name:           ${PROJECT_NAME}
Version:        ${RPM_VERSION}
Release:        ${RPM_RELEASE}
Summary:        Deepin Kernel Capture - eBPF-based system observation tools

License:        LGPL-2.1
URL:            https://github.com/your-repo/dkapture
BuildArch:      ${RPM_ARCH}

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

%files
%attr(755,root,root) /usr/bin/dk-*
%attr(755,root,root) /usr/lib/libdkapture.so
%attr(644,root,root) /usr/lib/dkapture/*.bpf.o
%attr(644,root,root) /usr/include/dkapture/dkapture.h
%attr(644,root,root) /etc/dkapture/policy/elfverify.pol
%attr(644,root,root) /etc/dkapture/policy/frtp.pol

%post
/sbin/ldconfig
echo "DKapture installation completed successfully!"

%postun
/sbin/ldconfig
echo "DKapture uninstallation completed successfully!"

%changelog
* $(LANG=en_US.UTF-8 date +"%a %b %d %Y") DKapture Team - ${RPM_VERSION}-${RPM_RELEASE}
- Initial build of ${PROJECT_NAME}
EOF

# Build RPM package
echo -e "${YELLOW}Building RPM package...${NC}"
rpmbuild -bb --buildroot "$(pwd)/${RPM_BUILD_DIR}" --define "_topdir $(pwd)/${BUILD_DIR}/rpmbuild" "${SPEC_DIR}/${PROJECT_NAME}.spec"

# Find the built RPM
RPM_FILE=$(find "${BUILD_DIR}/rpmbuild/RPMS/" -name "*.rpm" -type f | head -1)

if [ -f "$RPM_FILE" ]; then
    # Move RPM to current directory with standard name
    cp "$RPM_FILE" "${PACKAGE_NAME}.rpm"
    FINAL_RPM="${PACKAGE_NAME}.rpm"
else
    echo -e "${RED}Error: RPM file not found after build${NC}"
    exit 1
fi

# Verify RPM package
echo -e "${YELLOW}Verifying RPM package...${NC}"
echo -e "${BLUE}Package information:${NC}"
rpm -qip "${FINAL_RPM}"

echo -e "${BLUE}Package contents:${NC}"
rpm -qlp "${FINAL_RPM}"

# Count files
BIN_COUNT=$(find "${BIN_DIR}" -type f | wc -l)
LIB_COUNT=$(find "${LIB_DIR}" -type f | wc -l)
BPF_COUNT=$(find "${DKAPTURE_LIB_DIR}" -type f | wc -l)
INCLUDE_COUNT=$(find "${INCLUDE_DIR}" -type f | wc -l)

echo -e "${GREEN}RPM package build completed: ${FINAL_RPM}${NC}"
echo -e "${GREEN}Package size: $(du -h "${FINAL_RPM}" | cut -f1)${NC}"
echo -e "${GREEN}Contains: ${BIN_COUNT} executable files, ${LIB_COUNT} library files, ${BPF_COUNT} BPF object files, ${INCLUDE_COUNT} header files${NC}"

# Display installation instructions
echo -e "${YELLOW}Installation instructions:${NC}"
echo -e "sudo rpm -ivh ${FINAL_RPM}"
echo -e "Or: sudo dnf install ${FINAL_RPM}"
echo -e "Or: sudo yum install ${FINAL_RPM}"
echo -e ""
echo -e "${YELLOW}Upgrade instructions:${NC}"
echo -e "sudo rpm -Uvh ${FINAL_RPM}"
echo -e "Or: sudo dnf update ${FINAL_RPM}"
echo -e ""
echo -e "${YELLOW}Uninstall instructions:${NC}"
echo -e "sudo rpm -e ${PROJECT_NAME}"
echo -e ""
echo -e "${YELLOW}Package information:${NC}"
echo -e "rpm -qip ${FINAL_RPM}"
echo -e "rpm -qlp ${FINAL_RPM}"

# Clean build directory
cleanup

echo -e "${GREEN}Build completed!${NC}"