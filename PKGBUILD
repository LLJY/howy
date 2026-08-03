pkgbase=howy
pkgname=(howy-cpu howy-rocm howy-cuda)
pkgver=2.0.0
pkgrel=1
pkgdesc='Linux face authentication daemon — a howdy replacement'
arch=('x86_64')
url='https://github.com/LLJY/howy'
license=('GPL-2.0-only')
makedepends=(
  'cargo'
  'clang'
  'git'
  'onnxruntime=1.28.0'
  'protobuf'
  'systemd>=261'
)
_commit='5fb727b29d664c72b246f90c176d253ef74afe6f'
source=("${pkgbase}::git+https://github.com/LLJY/howy.git#commit=${_commit}")
sha256sums=('SKIP')

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
  ln -s pam_howy.so "${pkgdir}/usr/lib/security/pam_howdy.so"

  # Bridge release N deliberately retains package ownership and backup() of
  # the byte-identical previous-release payload. The secure template lives
  # under /usr/share and only the post_install bridge may exchange it.
  install -Dm644 packaging/config-release-n-legacy.toml "${pkgdir}/etc/howy/config.toml"
  install -Dm644 packaging/config.bootstrap.toml "${pkgdir}/usr/share/howy/config.bootstrap.toml"
  install -Dm644 packaging/00-howy-update-admission.hook "${pkgdir}/usr/share/libalpm/hooks/00-howy-update-admission.hook"
  install -Dm644 packaging/05-howy-config-stash.hook "${pkgdir}/usr/share/libalpm/hooks/05-howy-config-stash.hook"
  install -Dm644 packaging/10-howy-remove-prepare.hook "${pkgdir}/usr/share/libalpm/hooks/10-howy-remove-prepare.hook"
  install -Dm755 scripts/howy-v2-update-admission "${pkgdir}/usr/lib/howy/howy-v2-update-admission"
  install -Dm755 scripts/howy-v2-remove-prepare "${pkgdir}/usr/lib/howy/howy-v2-remove-prepare"
  install -Dm755 scripts/download-models.sh "${pkgdir}/usr/bin/howy-download-models"
  install -Dm755 scripts/enroll.py "${pkgdir}/usr/bin/howy-enroll"
  install -Dm755 scripts/howy-v2-update "${pkgdir}/usr/bin/howy-v2-update"
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

package_howy-cpu() {
  pkgdesc='Linux face authentication daemon intended for ONNX Runtime CPU backend'
  depends=('diffutils' 'onnxruntime=1.28.0' 'pam' 'systemd>=261')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
    'tpm2-tss: TPM-backed systemd credential provisioning'
  )
  provides=("howy=${pkgver}" "howdy=${pkgver}")
  conflicts=(
    'howy'
    'howy-git'
    'howy-cpu-git'
    'howy-rocm-git'
    'howy-cuda-git'
    'howy-rocm-mode0'
    'howdy'
    'howdy-git'
    'howy-rocm'
    'howy-cuda'
  )
  backup=('etc/howy/config.toml')
  install=howy.install

  _package_common "${pkgname}"
}

package_howy-rocm() {
  pkgdesc='Linux face authentication daemon intended for ONNX Runtime ROCm backend'
  depends=('diffutils' 'onnxruntime=1.28.0' 'pam' 'systemd>=261')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
    'tpm2-tss: TPM-backed systemd credential provisioning'
  )
  provides=("howy=${pkgver}" "howdy=${pkgver}")
  conflicts=(
    'howy'
    'howy-git'
    'howy-cpu-git'
    'howy-rocm-git'
    'howy-cuda-git'
    'howy-rocm-mode0'
    'howdy'
    'howdy-git'
    'howy-cpu'
    'howy-cuda'
  )
  backup=('etc/howy/config.toml')
  install=howy.install

  _package_common "${pkgname}"
}

package_howy-cuda() {
  pkgdesc='Linux face authentication daemon intended for ONNX Runtime CUDA backend'
  depends=('diffutils' 'onnxruntime=1.28.0' 'pam' 'systemd>=261')
  optdepends=(
    'curl: download default ONNX models'
    'ffmpeg: optional camera fallback when native V4L2 mmap capture fails'
    'unzip: extract default ONNX models'
    'uv: run the bundled howy-enroll helper'
    'v4l-utils: inspect and tune camera controls'
    'tpm2-tss: TPM-backed systemd credential provisioning'
  )
  provides=("howy=${pkgver}" "howdy=${pkgver}")
  conflicts=(
    'howy'
    'howy-git'
    'howy-cpu-git'
    'howy-rocm-git'
    'howy-cuda-git'
    'howy-rocm-mode0'
    'howdy'
    'howdy-git'
    'howy-cpu'
    'howy-rocm'
  )
  backup=('etc/howy/config.toml')
  install=howy.install

  _package_common "${pkgname}"
}
