#!/bin/bash

# DKapture DEB Package Builder
# DEB packaging script that meets pack-rule.txt requirements

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project information
PROJECT_NAME="dkapture"
VERSION="1.0.0"
ARCH=$(dpkg --print-architecture)
PACKAGE_NAME="${PROJECT_NAME}_${VERSION}_${ARCH}"

# Directory definitions
BUILD_DIR="build"
DEB_DIR="${BUILD_DIR}/deb"
INSTALL_DIR="${DEB_DIR}/usr"
BIN_DIR="${INSTALL_DIR}/bin"
LIB_DIR="${INSTALL_DIR}/lib"
INCLUDE_DIR="${INSTALL_DIR}/include"
CONTROL_DIR="${DEB_DIR}/DEBIAN"
if [ $(nproc) -gt 1 ]; then
    MAKE="make -j$(($(nproc)-1))"
else
    MAKE="make"
fi

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "${BUILD_DIR}"
}

# Error handling
trap cleanup EXIT

# Check dependencies function
check_dependencies() {
    echo -e "${BLUE}Checking build dependencies...${NC}"
    
    local missing_deps=()
    
    # Check basic tools
    command -v make >/dev/null 2>&1 || missing_deps+=("make")
    command -v dpkg-deb >/dev/null 2>&1 || missing_deps+=("dpkg-dev")
    command -v gcc >/dev/null 2>&1 || missing_deps+=("gcc")
    command -v g++ >/dev/null 2>&1 || missing_deps+=("g++")
    command -v clang >/dev/null 2>&1 || missing_deps+=("clang")
    command -v bpftool >/dev/null 2>&1 || missing_deps+=("bpftool")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing the following dependencies:${NC}"
        printf '%s\n' "${missing_deps[@]}"
        echo -e "${YELLOW}Please run: sudo apt-get install build-essential dpkg-dev clang llvm libbpf-dev${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All dependency checks passed${NC}"
}

# Verify build results function
verify_build() {
    echo -e "${BLUE}Verifying build results...${NC}"
    
    local missing_files=()
    
    # Check executable files in build/observe directory
    if [ ! -d "build/observe" ]; then
        missing_files+=("build/observe directory")
    else
        local observe_binaries=$(find build/observe -maxdepth 1 -type f -executable 2>/dev/null | wc -l)
        if [ "$observe_binaries" -eq 0 ]; then
            missing_files+=("executable files in build/observe directory")
        fi
    fi
    
    # Check executable files in build/filter directory
    if [ ! -d "build/filter" ]; then
        missing_files+=("build/filter directory")
    else
        local filter_binaries=$(find build/filter -maxdepth 1 -type f -executable 2>/dev/null | wc -l)
        if [ "$filter_binaries" -eq 0 ]; then
            missing_files+=("executable files in build/filter directory")
        fi
    fi
    
    # Check executable files in build/policy directory
    if [ ! -d "build/policy" ]; then
        missing_files+=("build/policy directory")
    else
        local policy_binaries=$(find build/policy -maxdepth 1 -type f -executable 2>/dev/null | wc -l)
        if [ "$policy_binaries" -eq 0 ]; then
            missing_files+=("executable files in build/policy directory")
        fi
    fi
    
    # Check dynamic library
    if [ ! -f "build/so/libdkapture.so" ]; then
        missing_files+=("libdkapture.so dynamic library")
    fi
    
    # Check demo program
    if [ ! -f "build/demo/demo" ]; then
        missing_files+=("demo program")
    fi
    
    # Check header file
    if [ ! -f "include/dkapture.h" ]; then
        missing_files+=("dkapture.h header file")
    fi
    
    if [ ${#missing_files[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing the following files after compilation:${NC}"
        printf '  - %s\n' "${missing_files[@]}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Build result verification passed${NC}"
}

echo -e "${GREEN}Starting DKapture DEB package build...${NC}"

# Check dependencies
check_dependencies

# Clean previous build
cleanup

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p "${BIN_DIR}"
mkdir -p "${LIB_DIR}"
mkdir -p "${INCLUDE_DIR}/${PROJECT_NAME}"
mkdir -p "${CONTROL_DIR}"

# Compile project (excluding googletest, test and tools)
echo -e "${YELLOW}Compiling project...${NC}"
echo -e "${BLUE}Cleaning previous compilation...${NC}"
${MAKE} clean || echo -e "${YELLOW}Warning: Clean failed (may be first compilation)${NC}"

echo -e "${BLUE}Compiling include module...${NC}"
${MAKE} include || { echo -e "${RED}Error: include module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling observe module...${NC}"
${MAKE} observe || { echo -e "${RED}Error: observe module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling filter module...${NC}"
${MAKE} filter || { echo -e "${RED}Error: filter module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling policy module...${NC}"
${MAKE} policy || { echo -e "${RED}Error: policy module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling so module...${NC}"
${MAKE} so || { echo -e "${RED}Error: so module compilation failed${NC}"; exit 1; }

echo -e "${BLUE}Compiling demo module...${NC}"
${MAKE} demo || { echo -e "${RED}Error: demo module compilation failed${NC}"; exit 1; }

# Verify build results
verify_build

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

# Collect header files to /usr/include/${PROJECT_NAME}
echo -e "${YELLOW}Collecting header files to /usr/include/${PROJECT_NAME}...${NC}"
if [[ -f "include/dkapture.h" ]]; then
    echo "  Copying: dkapture.h -> ${INCLUDE_DIR}/${PROJECT_NAME}/dkapture.h"
    cp "include/dkapture.h" "${INCLUDE_DIR}/${PROJECT_NAME}/dkapture.h"
else
    echo -e "${YELLOW}Warning: include/dkapture.h not found${NC}"
fi

# Create control file
echo -e "${YELLOW}Creating DEB control file...${NC}"
cat > "${CONTROL_DIR}/control" << EOF
Package: ${PROJECT_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: DKapture Team <dkapture@example.com>
Depends: libbpf1
Priority: optional
Section: utils
Description: Deepin Kernel Capture - eBPF-based system observation tools
 DKapture is a user-space toolset and dynamic library for observing
 and manipulating kernel data objects or behaviors. It is based on
 Linux kernel's emerging eBPF technology, which is safer than
 kernel module-based technologies like sysdig and systemtap.
 .
 Features include:
  - Network information collection
  - File system information collection
  - Process information collection
  - IO information collection
  - System call information collection
  - Scheduling information collection
  - Interrupt information collection
  - Memory information collection
EOF

# Create postinst script (executed after installation)
cat > "${CONTROL_DIR}/postinst" << 'EOF'
#!/bin/bash
set -e

# Set dynamic library permissions
if [ -f /usr/lib/libdkapture.so ]; then
    chmod 755 /usr/lib/libdkapture.so
fi

# Set executable file permissions
find /usr/bin -name "dk-*" -type f -exec chmod 755 {} \;

# Update dynamic library cache
ldconfig

echo "DKapture installation completed successfully!"
EOF

# Create postrm script (executed after removal)
cat > "${CONTROL_DIR}/postrm" << 'EOF'
#!/bin/bash
set -e

# Update dynamic library cache
ldconfig

echo "DKapture uninstallation completed successfully!"
EOF

# Set script permissions
chmod 755 "${CONTROL_DIR}/postinst"
chmod 755 "${CONTROL_DIR}/postrm"

# Calculate package size
echo -e "${YELLOW}Calculating package size...${NC}"
INSTALLED_SIZE=$(du -sk "${INSTALL_DIR}" | cut -f1)

# Update Installed-Size in control file
sed -i "s/^Priority: optional$/Priority: optional\nInstalled-Size: ${INSTALLED_SIZE}/" "${CONTROL_DIR}/control"

# Build deb package
echo -e "${YELLOW}Building DEB package...${NC}"
dpkg-deb --build "${DEB_DIR}" "${PACKAGE_NAME}.deb"

# Verify deb package
echo -e "${YELLOW}Verifying DEB package...${NC}"
echo -e "${BLUE}Package information:${NC}"
dpkg-deb --info "${PACKAGE_NAME}.deb"

echo -e "${BLUE}Package contents:${NC}"
dpkg-deb --contents "${PACKAGE_NAME}.deb"

# Count files
BIN_COUNT=$(find "${BIN_DIR}" -type f | wc -l)
LIB_COUNT=$(find "${LIB_DIR}" -type f | wc -l)
INCLUDE_COUNT=$(find "${INCLUDE_DIR}" -type f | wc -l)

echo -e "${GREEN}DEB package build completed: ${PACKAGE_NAME}.deb${NC}"
echo -e "${GREEN}Package size: $(du -h "${PACKAGE_NAME}.deb" | cut -f1)${NC}"
echo -e "${GREEN}Contains: ${BIN_COUNT} executable files, ${LIB_COUNT} library files, ${INCLUDE_COUNT} header files${NC}"

# Display installation instructions
echo -e "${YELLOW}Installation instructions:${NC}"
echo -e "sudo dpkg -i ${PACKAGE_NAME}.deb"
echo -e "sudo apt-get install -f  # If there are dependency issues"
echo -e ""
echo -e "${YELLOW}Uninstall instructions:${NC}"
echo -e "sudo dpkg -r ${PROJECT_NAME}"
echo -e ""
echo -e "${YELLOW}Cleanup instructions:${NC}"
echo -e "sudo dpkg -P ${PROJECT_NAME}  # Complete cleanup including configuration files"

# Clean build directory
cleanup

echo -e "${GREEN}Build completed!${NC}" 