# Maintainer: Adivor <adivor@gmail.com>
pkgname=bytesweep
pkgver=1.0.0
pkgrel=1
pkgdesc="Linux server monitoring dashboard with auto-cleanup agent"
arch=('any')
url="https://github.com/iu2vwk-ita/swiftserver"
license=('MIT')
depends=('python>=3.8' 'python-pip' 'systemd')
makedepends=('git')
install=bytesweep.install
source=(
    "server_monitor.py"
    "cleanup.py"
    "auto_cleanup.py"
    "config.py"
    "requirements.txt"
    "static/index.html"
)
sha256sums=('SKIP')

package() {
    install_dir="$pkgdir/opt/server-monitor"

    mkdir -p "$install_dir/static"
    mkdir -p "$install_dir/logs"

    install -Dm755 server_monitor.py "$install_dir/server_monitor.py"
    install -Dm644 cleanup.py        "$install_dir/cleanup.py"
    install -Dm644 auto_cleanup.py   "$install_dir/auto_cleanup.py"
    install -Dm644 config.py         "$install_dir/config.py"
    install -Dm644 requirements.txt  "$install_dir/requirements.txt"
    install -Dm644 static/index.html "$install_dir/static/index.html"
}
