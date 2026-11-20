"""UI language (Indonesian / English).

The Indonesian text is the key; _() returns the English text when the language is 'en'.
Missing translations fall back to Indonesian. tests/test_i18n.py checks that every _() literal
in the GUI has an English entry.
"""
from __future__ import annotations

_lang = "id"


def set_lang(lang: str) -> None:
    global _lang
    _lang = lang if lang in ("id", "en") else "id"


def lang() -> str:
    return _lang


def _(text: str) -> str:
    if _lang == "en":
        return EN.get(text, text)
    return text


EN: dict[str, str] = {
    # ------------------------------------------------------------- general / header
    "Siap. Semua fitur berjalan offline.": "Ready. All features work offline.",
    "Toolkit jaringan multi-vendor  •  v{version}": "Multi-vendor network toolkit  •  v{version}",
    "Mode terang": "Light mode",
    "Mode malam": "Dark mode",
    "Tunggu proses yang sedang berjalan selesai sebelum mengganti bahasa.":
        "Wait for the running job to finish before changing the language.",
    "Bahasa diganti ke Bahasa Indonesia.": "Language changed to Bahasa Indonesia.",
    "Bahasa diganti ke English.": "Language changed to English.",
    "Drag & drop tidak tersedia (tkinterdnd2 tidak ditemukan). Gunakan tombol Buka file.":
        "Drag & drop is not available (tkinterdnd2 not found). Use the Open file button.",
    "Pengambilan log masih berjalan. Keluar?": "Log collection is still running. Quit?",
    "Semua file": "All files",
    "Disimpan: {path}": "Saved: {path}",
    "Diexport: {path}": "Exported: {path}",
    "Dibuka: {path}": "Opened: {path}",
    "Simpan": "Save",
    "Batal": "Cancel",
    "Stop": "Stop",
    "Bersihkan": "Clear",
    "Buka file...": "Open file...",
    "Export CSV...": "Export CSV...",
    "Import CSV...": "Import CSV...",
    "Nama": "Name",
    "Port": "Port",
    "Paralel": "Parallel",
    "Detail": "Details",
    "Keterangan": "Notes",
    "Semua": "All",
    "Total": "Total",
    "Opsi": "Options",
    "Mode": "Mode",
    "Waktu": "Time",
    "Default": "Default",
    "GAGAL": "FAILED",
    "Gagal:": "Failed:",
    # ------------------------------------------------------------------ convert
    "Deteksi otomatis": "Auto-detect",
    "Parser bawaan (semua vendor)": "Built-in parser (all vendors)",
    "Batfish jika tersedia, lalu bawaan": "Batfish when available, then built-in",
    "Batfish saja (Cisco/Arista/Juniper/Fortinet)": "Batfish only (Cisco/Arista/Juniper/Fortinet)",
    "Sumber:": "Source:",
    "Tujuan:": "Target:",
    "Parser:": "Parser:",
    "Convert": "Convert",
    "Output jadi input (balik)": "Output to input (reverse)",
    "Simpan output...": "Save output...",
    "Salin output": "Copy output",
    "Convert banyak file...": "Convert many files...",
    "Konfigurasi sumber  (paste, buka, atau drop file di sini)": "Source configuration  (paste, open, or drop a file here)",
    "Hasil konversi": "Converted configuration",
    "Laporan konversi": "Conversion report",
    "Terdeteksi: {vendor}": "Detected: {vendor}",
    "Vendor belum dikenali": "Vendor not recognized",
    "Buka konfigurasi": "Open configuration",
    "Konfigurasi": "Configuration",
    "Konversi gagal:\n{error}": "Conversion failed:\n{error}",
    "Selesai: {src} -> {dst}, {warn} peringatan, {skip} baris tidak dikonversi":
        "Done: {src} -> {dst}, {warn} warnings, {skip} lines not converted",
    "Output disalin ke clipboard": "Output copied to the clipboard",
    "Pilih banyak konfigurasi": "Select configurations",
    "{count} file berhasil dikonversi ke:\n{folder}": "{count} files converted to:\n{folder}",
    # --------------------------------------------------------------- collector
    "Device": "Device",
    "IP / host": "IP / host",
    "Protokol": "Protocol",
    "Username/password kosong = pakai kredensial default.": "Empty username/password = use the default credentials.",
    "IP wajib diisi.": "IP is required.",
    "Daftar device": "Devices",
    "Tambah": "Add",
    "Edit": "Edit",
    "Hapus": "Remove",
    "Format CSV: host,ip,vendor,port,protocol,username,password": "CSV format: host,ip,vendor,port,protocol,username,password",
    "Kredensial default & opsi": "Default credentials & options",
    "Timeout/command (s)": "Timeout/command (s)",
    "Mulai ambil log": "Start collecting",
    "Buka folder hasil": "Open results folder",
    "Kirim config ke Topologi": "Send configs to Topology",
    "Aktivitas": "Activity",
    "Command per vendor (satu baris satu command)": "Commands per vendor (one command per line)",
    "Gagal membaca CSV:\n{error}": "Could not read the CSV:\n{error}",
    "{count} device diimport": "{count} devices imported",
    "Vendor tidak dikenal untuk: {names}\nEdit device tersebut dan pilih vendor.":
        "Unknown vendor for: {names}\nEdit those devices and choose a vendor.",
    "Inventory disimpan (tanpa password): {path}": "Inventory saved (without passwords): {path}",
    "Command disimpan: {path}": "Commands saved: {path}",
    "Tambahkan device atau import CSV dulu.": "Add a device or import a CSV first.",
    "Pilih vendor untuk: {names}": "Choose a vendor for: {names}",
    "Username kosong untuk: {names}": "Username missing for: {names}",
    "menunggu": "waiting",
    "== Mulai {count} device -> {path}": "== Starting {count} devices -> {path}",
    "== Selesai. Hasil: {path}": "== Done. Results: {path}",
    "Pengambilan log selesai: {path}": "Log collection finished: {path}",
    "konek {target}": "connecting {target}",
    "konek...": "connecting...",
    "selesai": "done",
    "GAGAL: {error}": "FAILED: {error}",
    "== Stop diminta, menunggu command yang sedang jalan selesai...":
        "== Stop requested, waiting for the running commands to finish...",
    "Belum ada config hasil pengambilan log.\nPastikan command config (mis. 'show running-config') ada di daftar.":
        "No collected configurations yet.\nMake sure a config command (e.g. 'show running-config') is in the list.",
    # ----------------------------------------------------------------- topology
    "Tambah config...": "Add configs...",
    "Tambah folder...": "Add folder...",
    "Reset": "Reset",
    "Peer BGP eksternal": "External BGP peers",
    "Subnet LAN (stub)": "LAN subnets (stub)",
    "Atur ulang layout": "Re-layout",
    "Export draw.io...": "Export draw.io...",
    "Export SVG...": "Export SVG...",
    "Export CSV link...": "Export link CSV...",
    "File dimuat": "Loaded files",
    "Hapus terpilih": "Remove selected",
    "Pilih konfigurasi router": "Select router configurations",
    "{dev} device, {l3} link IP, {bgp} sesi BGP": "{dev} devices, {l3} IP links, {bgp} BGP sessions",
    "Topologi: {dev} device, {links} link": "Topology: {dev} devices, {links} links",
    "Drop file konfigurasi router di sini\n(Cisco, Juniper, MikroTik, Huawei, Fortinet,\nArista, H3C, Nokia, VyOS, Aruba)\n\natau klik 'Tambah config...'":
        "Drop router configuration files here\n(Cisco, Juniper, MikroTik, Huawei, Fortinet,\nArista, H3C, Nokia, VyOS, Aruba)\n\nor click 'Add configs...'",
    "Belum ada topologi.": "No topology yet.",
    # ---------------------------------------------------------------- bulk ping
    "Target": "Target",
    "Kirim": "Sent",
    "Terima": "Recv",
    "Dari inventory": "From inventory",
    "# satu target per baris, contoh:": "# one target per line, for example:",
    "Jumlah ping": "Ping count",
    "Timeout (ms)": "Timeout (ms)",
    "Ukuran (byte)": "Size (bytes)",
    "Ulangi tiap (detik)": "Repeat every (s)",
    "Cari nama (reverse DNS)": "Resolve names (reverse DNS)",
    "Mulai ping": "Start ping",
    "Tampilkan:": "Show:",
    "Belum ada hasil.": "No results yet.",
    "Teks/CSV": "Text/CSV",
    "Inventory di tab Log Collector masih kosong.": "The Log Collector inventory is empty.",
    "Isi minimal satu target.": "Enter at least one target.",
    "Ping {count} target...": "Pinging {count} targets...",
    "Putaran {round}  |  UP {up}  |  DOWN {down}  |  PARTIAL {partial}  |  ERROR {error}  |  total {total}  |  {time}":
        "Round {round}  |  UP {up}  |  DOWN {down}  |  PARTIAL {partial}  |  ERROR {error}  |  total {total}  |  {time}",
    # --------------------------------------------------------------- speed test
    "Internet (Cloudflare)": "Internet (Cloudflare)",
    "URL server sendiri (HTTP)": "Your own server URL (HTTP)",
    "LAN ke NetManage lain": "LAN to another NetManage",
    "Pengaturan tes": "Test settings",
    "URL file": "File URL",
    "Server LAN (IP)": "LAN server (IP)",
    "Durasi per arah (detik)": "Duration per direction (s)",
    "Stream paralel": "Parallel streams",
    "Tes upload": "Test upload",
    "Mulai speed test": "Start speed test",
    "Mode server LAN (laptop ini)": "LAN server mode (this laptop)",
    "Jalankan server": "Start server",
    "Hentikan server": "Stop server",
    "Server mati.": "Server stopped.",
    "IP laptop ini: {ips}": "This laptop's IP: {ips}",
    "Riwayat": "History",
    "Butuh koneksi internet. Mengukur ke server speed.cloudflare.com terdekat. Data yang dikirim hanya byte acak.":
        "Needs an internet connection. Measures against the nearest speed.cloudflare.com server. Only random bytes are sent.",
    "Download berulang dari URL (misalnya file besar di web server internal). Upload hanya jalan jika server menerima POST.":
        "Downloads the URL repeatedly (for example a large file on an internal web server). Upload only works when the server accepts POST.",
    "Offline. Jalankan 'Mode server LAN' di NetManage laptop lain, lalu isi IP laptop itu. Cocok untuk mengukur throughput link antar site/VLAN.":
        "Offline. Start 'LAN server mode' in NetManage on another laptop, then enter that laptop's IP. Good for measuring link throughput between sites/VLANs.",
    "Server gagal jalan di port {port}:\n{error}": "The server could not start on port {port}:\n{error}",
    "Server speed test LAN aktif di port {port}. Izinkan di Windows Firewall jika diminta.":
        "LAN speed test server running on port {port}. Allow it in Windows Firewall if asked.",
    "Isi URL file untuk diunduh.": "Enter the URL of a file to download.",
    "Isi IP laptop yang menjalankan server LAN NetManage.": "Enter the IP of the laptop running the NetManage LAN server.",
    "Mengukur latency...": "Measuring latency...",
    "Mengukur download...": "Measuring download...",
    "Mengukur upload...": "Measuring upload...",
    "Selesai.": "Done.",
    "Selesai dengan catatan: {error}": "Done with a note: {error}",
    "Speed test: download {down} Mbps, upload {up} Mbps, ping {ping} ms":
        "Speed test: download {down} Mbps, upload {up} Mbps, ping {ping} ms",
    # ---------------------------------------------------------- conversion report
    "Sumber : {src}  (parser: {engine})": "Source : {src}  (parser: {engine})",
    "Tujuan : {dst}": "Target : {dst}",
    "Device : {dev}": "Device : {dev}",
    "Terkonversi: {ifs} interface, {vlans} VLAN, {routes} static route, OSPF {ospf}, BGP {bgp} neighbor":
        "Converted: {ifs} interfaces, {vlans} VLANs, {routes} static routes, OSPF {ospf}, BGP {bgp} neighbors",
    "ya": "yes",
    "tidak": "no",
    "Policy     : {rm} route-map, {pl} prefix-list, {cl} community-list, {acl} ACL ({aclb} terpasang di interface), {qos} QoS policy ({qosb} terpasang)":
        "Policy     : {rm} route-maps, {pl} prefix-lists, {cl} community-lists, {acl} ACLs ({aclb} applied to interfaces), {qos} QoS policies ({qosb} applied)",
    "MAPPING INTERFACE (periksa dan sesuaikan dengan port fisik sebenarnya):":
        "INTERFACE MAPPING (check against the real physical ports):",
    "PERINGATAN ({count}):": "WARNINGS ({count}):",
    "TIDAK DIKONVERSI ({count} baris, konversi manual):": "NOT CONVERTED ({count} lines, convert manually):",
}
