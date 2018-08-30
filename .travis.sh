#!/usr/bin/env bash

git submodule update --init --recursive

if [ -n "${LIBCXX_BUILD}" ]; then
  # Checkout LLVM sources
  git clone --depth=1 https://github.com/llvm-mirror/llvm.git llvm-source
  git clone --depth=1 https://github.com/llvm-mirror/libcxx.git llvm-source/projects/libcxx
  git clone --depth=1 https://github.com/llvm-mirror/libcxxabi.git llvm-source/projects/libcxxabi

  # Setup libc++ options
  if [ -z "$BUILD_32_BITS" ]; then
    export BUILD_32_BITS=OFF && echo disabling 32 bit build
  fi

  # Build and install libc++ (Use unstable ABI for better sanitizer coverage)
  mkdir llvm-build && cd llvm-build
  cmake -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_CXX_COMPILER=${COMPILER} \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/usr \
        -DLIBCXX_ABI_UNSTABLE=ON \
        -DLLVM_USE_SANITIZER=${LIBCXX_SANITIZER} \
        -DLLVM_BUILD_32_BITS=${BUILD_32_BITS} \
        ../llvm-source
  make cxx -j2
  sudo make install-cxxabi install-cxx
  cd ../
fi


if [ -n "${LIBCXX_BUILD}" ]; then
  if [ "${BUILD_32_BITS}" == "ON" ]; then
    export EXTRA_C_FLAGS="-m32"
    export EXTRA_CXX_FLAGS="-stdlib=libc++ -m32"
  else
    export EXTRA_CXX_FLAGS="-stdlib=libc++"
  fi
fi

export EXTRA_C_FLAGS="${EXTRA_C_FLAGS} ${EXTRA_FLAGS}"
export EXTRA_CXX_FLAGS="${EXTRA_CXX_FLAGS} ${EXTRA_FLAGS}"

echo "CFlags: ${EXTRA_C_FLAGS}" "Compiler: ${C_COMPILER}"
echo "CXXFlags: ${EXTRA_CXX_FLAGS}" "Compiler: ${COMPILER}"

