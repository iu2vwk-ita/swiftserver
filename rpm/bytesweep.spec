%define _version 1.0.0
%define _release 1
%define _service bytesweep
%define _install_dir /opt/server-monitor

Name:           bytesweep
Version:        %{_version}
Release:        %{_release}%{?dist}
Summary:        Linux server monitoring dashboard with auto-cleanup

License:        MIT
URL:            https://github.com/iu2vwk-ita/swiftserver
Source0:        https://github.com/iu2vwk-ita/swiftserver/archive/refs/tags/v%{_version}.tar.gz

BuildArch:      noarch
Requires:       python3 >= 3.8
Requires:       python3-pip
Requires:       systemd

%description
ByteSweep is a lightweight, real-time Linux server monitoring
dashboard with integrated disk cleanup utilities -- perfect for
purging heavy AI-generated temporary files and cache.

Features:
 - Real-time CPU, memory, disk, and network metrics
 - Interactive charts (Chart.js)
 - Top processes table
 - File manager with directory browsing and deletion
 - One-click maintenance cleanup (APT, logs, Docker, caches)
 - Auto-cleanup agent (hourly systemd timer)
 - Responsive dark UI
 - 10 built-in cleaners

%prep
# No source archive needed -- files are copied directly in %install
# For a dist tarball build, this would extract the source

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_install_dir}/static
mkdir -p %{buildroot}%{_install_dir}/logs

# Copy application files
cp server_monitor.py %{buildroot}%{_install_dir}/
cp cleanup.py        %{buildroot}%{_install_dir}/
cp auto_cleanup.py   %{buildroot}%{_install_dir}/
cp config.py         %{buildroot}%{_install_dir}/
cp requirements.txt  %{buildroot}%{_install_dir}/
cp -r static/*       %{buildroot}%{_install_dir}/static/

%post
# Set up Python virtual environment
python3 -m venv %{_install_dir}/venv
%{_install_dir}/venv/bin/pip install --quiet -r %{_install_dir}/requirements.txt

# Install systemd service
cat > /etc/systemd/system/%{_service}.service << 'UNIT'
[Unit]
Description=ByteSweep - Server Monitor & Auto-Cleanup Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/server-monitor
ExecStart=/opt/server-monitor/venv/bin/python /opt/server-monitor/server_monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/%{_service}-cleanup.service << 'UNIT'
[Unit]
Description=ByteSweep Auto-Cleanup
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/server-monitor
ExecStart=/opt/server-monitor/venv/bin/python /opt/server-monitor/auto_cleanup.py
UNIT

cat > /etc/systemd/system/%{_service}-cleanup.timer << 'UNIT'
[Unit]
Description=ByteSweep Auto-Cleanup Timer (hourly)

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable %{_service}
systemctl enable %{_service}-cleanup.timer
systemctl start %{_service}
systemctl start %{_service}-cleanup.timer

echo "ByteSweep v%{_version} installed successfully!"
echo "Dashboard: http://\$(hostname -I | awk '{print \$1}'):5000"

%preun
if [ $1 -eq 0 ]; then
    systemctl stop %{_service} 2>/dev/null || true
    systemctl stop %{_service}-cleanup.timer 2>/dev/null || true
    systemctl disable %{_service} 2>/dev/null || true
    systemctl disable %{_service}-cleanup.timer 2>/dev/null || true
    rm -f /etc/systemd/system/%{_service}.service
    rm -f /etc/systemd/system/%{_service}-cleanup.service
    rm -f /etc/systemd/system/%{_service}-cleanup.timer
    systemctl daemon-reload 2>/dev/null || true
    rm -rf %{_install_dir}
fi

%files
%defattr(-,root,root)
%{_install_dir}/server_monitor.py
%{_install_dir}/cleanup.py
%{_install_dir}/auto_cleanup.py
%{_install_dir}/config.py
%{_install_dir}/requirements.txt
%{_install_dir}/static/

%changelog
* Tue May 19 2026 Adivor <adivor@gmail.com> - 1.0.0-1
- Initial RPM release
- Server monitoring dashboard with 10 cleanup operations
- File manager, auto-cleanup timer, responsive UI
