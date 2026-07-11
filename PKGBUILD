pkgbase=howy-git
pkgname=(howy-cpu-git howy-rocm-git howy-cuda-git)
_basever=0.1.0
pkgver=0.1.0.r19.g4aceddb
pkgrel=1
pkgdesc='Linux face authentication daemon — a howdy replacement'
arch=('x86_64')
url='https://github.com/LLJY/howy'
license=('GPL-2.0-only')
makedepends=(
  'cargo'
  'clang'
  'git'
  'onnxruntime-cpu'
  'protobuf'
)
source=("${pkgbase}::git+https://github.com/LLJY/howy.git")
sha256sums=('SKIP')

pkgver() {
  cd "${srcdir}/${pkgbase}"
  printf '%s.r%s.g%s\n' "${_basever}" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
  cd "${srcdir}/${pkgbase}"
  cargo fetch --locked
}

build() {
  cd "${srcdir}/${pkgbase}"

  export CARGO_HOME="${srcdir}/cargo-home"
  export CARGO_TARGET_DIR="${srcdir}/target"
  export CARGO_BUILD_RUSTFLAGS='-C target-cpu=x86-64'
  export ORT_LIB_PATH=/usr/lib
  export ORT_PREFER_DYNAMIC_LINK=1

  cargo build --frozen --release -p howy-daemon -p howy-cli -p howy-pam
}

_install_units() {
  install -Dm644 /dev/stdin "${pkgdir}/usr/lib/systemd/system/howy.service" <<'EOF'
[Unit]
Description=howy Face Authentication Daemon
Documentation=https://github.com/LLJY/howy
After=network.target
Requires=howy.socket

[Service]
Type=simple
ExecStart=/usr/bin/howyd
Restart=on-failure
RestartSec=5
Environment="RUST_LOG=info"
SupplementaryGroups=video render
KeyringMode=shared

[Install]
WantedBy=multi-user.target
EOF

  install -Dm644 /dev/stdin "${pkgdir}/usr/lib/systemd/system/howy.socket" <<'EOF'
[Unit]
Description=howy Face Authentication Socket
Documentation=https://github.com/LLJY/howy

[Socket]
ListenStream=/run/howy/howy.sock
SocketMode=0666
DirectoryMode=0755
RuntimeDirectory=howy

[Install]
WantedBy=sockets.target
EOF
}

_package_common() {
  local _pkgname="$1"

  cd "${srcdir}/${pkgbase}"

  install -Dm755 "${srcdir}/target/release/howyd" "${pkgdir}/usr/bin/howyd"
  install -Dm755 "${srcdir}/target/release/howy" "${pkgdir}/usr/bin/howy"
  install -Dm644 "${srcdir}/target/release/libpam_howy.so" "${pkgdir}/usr/lib/security/pam_howy.so"

  install -Dm644 config.toml "${pkgdir}/etc/howy/config.toml"
  install -Dm755 scripts/download-models.sh "${pkgdir}/usr/bin/howy-download-models"
  install -Dm755 scripts/enroll.py "${pkgdir}/usr/bin/howy-enroll"
  install -Dm644 README.md "${pkgdir}/usr/share/doc/${_pkgname}/README.md"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${_pkgname}/LICENSE"

  install -d "${pkgdir}/etc/howy/models"
  install -d "${pkgdir}/usr/share/howy/onnx-data"
  install -d "${pkgdir}/var/cache/howy"
  install -d "${pkgdir}/var/log/howy"

  _install_units
}

package_howy-cpu-git() {
  pkgdesc='Linux face authentication daemon using ONNX Runtime CPU backend'
  depends=('onnxruntime-cpu' 'pam')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
  )
  provides=("howy=${pkgver}")
  conflicts=('howy' 'howy-rocm-git' 'howy-cuda-git')
  backup=('etc/howy/config.toml')

  _package_common "${pkgname}"
}

package_howy-rocm-git() {
  pkgdesc='Linux face authentication daemon using ONNX Runtime ROCm backend'
  depends=('onnxruntime-rocm' 'pam')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
  )
  provides=("howy=${pkgver}")
  conflicts=('howy' 'howy-cpu-git' 'howy-cuda-git')
  backup=('etc/howy/config.toml')

  _package_common "${pkgname}"
}

package_howy-cuda-git() {
  pkgdesc='Linux face authentication daemon using ONNX Runtime CUDA backend'
  depends=('onnxruntime-cuda' 'pam')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
  )
  provides=("howy=${pkgver}")
  conflicts=('howy' 'howy-cpu-git' 'howy-rocm-git')
  backup=('etc/howy/config.toml')

  _package_common "${pkgname}"
}
