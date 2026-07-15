pkgbase=howy-git
pkgname=(howy-cpu-git howy-rocm-git howy-cuda-git)
_basever=0.1.0
pkgver=0.1.0.r26.g2dfe39e
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
  'systemd>=261'
)
source=("${pkgbase}::git+https://github.com/LLJY/howy.git")
sha256sums=('SKIP')

pkgver() {
  cd "${srcdir}/${pkgbase}"
  printf '%s.r%s.g%s\n' "${_basever}" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
  cd "${srcdir}/${pkgbase}"

  export CARGO_HOME="${srcdir}/cargo-home"
  export CARGO_TARGET_DIR="${srcdir}/target"
  export CARGO_BUILD_RUSTFLAGS='-C target-cpu=x86-64'
  export ORT_LIB_PATH=/usr/lib
  export ORT_PREFER_DYNAMIC_LINK=1

  cargo fetch --locked
}

build() {
  cd "${srcdir}/${pkgbase}"

  export CARGO_HOME="${srcdir}/cargo-home"
  export CARGO_TARGET_DIR="${srcdir}/target"
  export CARGO_BUILD_RUSTFLAGS='-C target-cpu=x86-64'
  export ORT_LIB_PATH=/usr/lib
  export ORT_PREFER_DYNAMIC_LINK=1

  cargo build --frozen --release \
    -p howy-config-bridge \
    -p howy-daemon \
    -p howy-cli \
    -p howy-pam
}

_package_common() {
  local _pkgname="$1"

  cd "${srcdir}/${pkgbase}"

  install -Dm755 "${srcdir}/target/release/howyd" "${pkgdir}/usr/bin/howyd"
  install -Dm755 "${srcdir}/target/release/howy" "${pkgdir}/usr/bin/howy"
  install -Dm755 "${srcdir}/target/release/howy-config-bridge" "${pkgdir}/usr/lib/howy/howy-config-bridge"
  install -Dm644 "${srcdir}/target/release/libpam_howy.so" "${pkgdir}/usr/lib/security/pam_howy.so"

  # Bridge release N deliberately retains package ownership and backup() of
  # the byte-identical previous-release payload. The secure template lives
  # under /usr/share and only the post_install bridge may exchange it.
  install -Dm644 packaging/config-release-n-legacy.toml "${pkgdir}/etc/howy/config.toml"
  install -Dm644 packaging/config.bootstrap.toml "${pkgdir}/usr/share/howy/config.bootstrap.toml"
  install -Dm644 packaging/05-howy-config-stash.hook "${pkgdir}/usr/share/libalpm/hooks/05-howy-config-stash.hook"
  install -Dm755 scripts/download-models.sh "${pkgdir}/usr/bin/howy-download-models"
  install -Dm755 scripts/enroll.py "${pkgdir}/usr/bin/howy-enroll"
  install -Dm644 systemd/howy.service "${pkgdir}/usr/lib/systemd/system/howy.service"
  install -Dm644 systemd/howy.socket "${pkgdir}/usr/lib/systemd/system/howy.socket"
  install -Dm644 sysusers.d/howy.conf "${pkgdir}/usr/lib/sysusers.d/howy.conf"
  install -Dm644 README.md "${pkgdir}/usr/share/doc/${_pkgname}/README.md"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${_pkgname}/LICENSE"

  install -d -o root -g root -m 0700 \
    "${pkgdir}/etc/howy" \
    "${pkgdir}/etc/howy/models" \
    "${pkgdir}/etc/howy/models/mode1" \
    "${pkgdir}/etc/credstore.encrypted" \
    "${pkgdir}/var/lib/howy" \
    "${pkgdir}/var/lib/howy/security-state" \
    "${pkgdir}/var/lib/howy/security-state/unadopted" \
    "${pkgdir}/var/lib/howy/config-bridge" \
    "${pkgdir}/var/cache/howy" \
    "${pkgdir}/var/log/howy"
  install -d -o root -g root -m 0755 \
    "${pkgdir}/etc/systemd/system/howy.service.d" \
    "${pkgdir}/usr/share/howy/onnx-data"

}

package_howy-cpu-git() {
  pkgdesc='Linux face authentication daemon using ONNX Runtime CPU backend'
  depends=('onnxruntime-cpu' 'pam' 'systemd>=261')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
    'tpm2-tss: TPM-backed systemd credential provisioning'
  )
  provides=("howy=${pkgver}")
  conflicts=('howy' 'howy-rocm-git' 'howy-cuda-git')
  backup=('etc/howy/config.toml')
  install=howy.install

  _package_common "${pkgname}"
}

package_howy-rocm-git() {
  pkgdesc='Linux face authentication daemon using ONNX Runtime ROCm backend'
  depends=('onnxruntime-rocm' 'pam' 'systemd>=261')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
    'tpm2-tss: TPM-backed systemd credential provisioning'
  )
  provides=("howy=${pkgver}")
  conflicts=('howy' 'howy-cpu-git' 'howy-cuda-git')
  backup=('etc/howy/config.toml')
  install=howy.install

  _package_common "${pkgname}"
}

package_howy-cuda-git() {
  pkgdesc='Linux face authentication daemon using ONNX Runtime CUDA backend'
  depends=('onnxruntime-cuda' 'pam' 'systemd>=261')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
    'tpm2-tss: TPM-backed systemd credential provisioning'
  )
  provides=("howy=${pkgver}")
  conflicts=('howy' 'howy-cpu-git' 'howy-rocm-git')
  backup=('etc/howy/config.toml')
  install=howy.install

  _package_common "${pkgname}"
}
