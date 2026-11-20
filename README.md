# NetManage

Aplikasi desktop offline (Windows EXE) untuk pekerjaan jaringan multi-vendor:

1. **Convert Config**: konversi konfigurasi antar 10 vendor, dua arah (any-to-any).
2. **Log Collector**: ambil output command dari banyak device sekaligus via SSH/Telnet.
3. **Topology Mapper**: drop file konfigurasi router, topologi tergambar otomatis.

Vendor: Cisco IOS/IOS-XE, Juniper Junos, MikroTik RouterOS v7, Huawei VRP, Fortinet FortiOS,
Arista EOS, H3C Comware, Nokia SR OS (classic CLI), VyOS, Aruba AOS-CX.

## Menjalankan

- EXE: `dist\NetManage.exe` (satu file, tidak perlu Python). Folder `output\` dibuat di sebelah EXE.
- Dari source:

```
py -3.13 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

- Build ulang EXE: `.venv\Scripts\pyinstaller NetManage.spec --noconfirm --clean`
- Cek EXE hasil build: `dist\NetManage.exe --selftest`, lalu buka `dist\output\selftest.txt`.

## Tampilan

- **Mode malam / mode terang:** tombol di kanan atas header. Title bar Windows ikut gelap.
- **Bahasa:** pilihan Bahasa Indonesia / English di header. Ganti bahasa memuat ulang tampilan, tapi
  input yang sedang dikerjakan tetap ada (config di tab Convert, inventory, file topologi, target ping,
  riwayat speed test). Tidak bisa diganti saat log collector, ping, atau speed test sedang berjalan.
  Laporan konversi ikut diterjemahkan; isi peringatan per vendor masih berbahasa Indonesia.
- Pilihan tema dan bahasa disimpan di `settings.json` di sebelah EXE.
- Logo ada di `netmanage/assets/`. Untuk mengganti logo:
  `.venv\Scripts\python tools\make_assets.py <gambar logo>` lalu build ulang (butuh Pillow, hanya saat build).

## Cara kerja konversi

```
config sumber -> parser vendor -> model netral (Device) -> template Jinja2 vendor tujuan -> config baru
```

Karena semua vendor lewat model netral yang sama, setiap pasangan vendor bisa dikonversi bolak-balik.
Yang dikonversi: hostname, interface (deskripsi, IP primer/secondary, shutdown, MTU, sub-interface
dot1q, VRF), VLAN, switchport access/trunk, static route (next-hop, interface, Null/blackhole,
distance), OSPF (router-id, area, network/interface, passive, cost, redistribute), BGP (AS, router-id,
neighbor, update-source, multihop, next-hop-self, network, redistribute), DNS, NTP, syslog, SNMP.

### Route-map, ACL, QoS

| Fitur | Yang dikonversi |
|---|---|
| Prefix-list | permit/deny, `ge`/`le` (rentang panjang prefix) |
| Community-list | standard, permit/deny |
| Route-map | match prefix-list, community, tag; set local-preference, metric/MED, community (+additive), next-hop, as-path prepend, weight, tag; dipasang di neighbor BGP (in/out) dan di redistribute OSPF/BGP |
| ACL | standard/extended, protokol, alamat sumber/tujuan, port (eq/range/gt/lt), established, log, remark; dipasang di interface (in/out) |
| QoS | class (match DSCP, match ACL, match any), set DSCP, police, shape, bandwidth (kbps/persen), priority; dipasang di interface (input/output) |

Padanan per vendor:

| Vendor | Route-map | ACL | QoS |
|---|---|---|---|
| Cisco IOS | route-map + ip prefix-list | ip access-list / access-list bernomor | MQC class-map + policy-map |
| Arista EOS | route-map + ip prefix-list | ip access-list | class-map/policy-map type qos (input saja) |
| Aruba AOS-CX | route-map + ip prefix-list | access-list ip | class ip + policy (dscp, cir, local-priority) |
| Huawei VRP | route-policy + ip ip-prefix | acl (basic/advance) + traffic-filter | traffic classifier/behavior/policy |
| H3C Comware | route-policy + ip prefix-list | acl (basic/advanced) + packet-filter | traffic classifier/behavior + qos policy |
| Juniper Junos | policy-statement + route-filter | firewall filter | firewall filter + policer + class-of-service scheduler |
| MikroTik | /routing filter rule | /ip firewall filter (chain + jump) | mangle mark-packet + queue tree |
| Fortinet | router route-map + prefix-list | firewall policy + address/service | traffic-shaper + shaping-policy |
| Nokia SR OS | policy-statement + prefix-list | ip-filter | tidak dikonversi (model sap-ingress berbeda) |
| VyOS | policy route-map + prefix-list | firewall ipv4 name + jump | qos policy shaper / limiter |

Fitur yang tidak punya padanan di vendor tujuan (misalnya `set weight` di Junos, priority/bandwidth di
Arista, QoS di Nokia) tidak dibuang diam-diam: semuanya muncul sebagai peringatan di laporan.
Nomor ACL yang tidak valid di vendor tujuan (misalnya ACL `3000` Huawei ke Cisco) otomatis diganti nama
menjadi `ACL-3000`, dan penggantian itu tercatat di laporan.

Setiap hasil konversi disertai **laporan**:

- ringkasan jumlah route-map, prefix-list, ACL, dan QoS policy yang terkonversi;
- tabel mapping nama interface (mis. `GigabitEthernet0/1 -> ge-0/0/1`), periksa terhadap port fisik asli;
- peringatan untuk fitur yang tidak punya padanan langsung di vendor tujuan;
- daftar baris yang **tidak dikonversi** (NAT, VPN, MPLS, dll.) untuk dikerjakan manual.

Tombol **Output jadi input (balik)** menukar vendor dan memakai hasil sebagai input, untuk cek bolak-balik.

### Template Jinja2

Template ada di `netmanage/templates/<vendor>.j2`. Untuk mengubah format output tanpa build ulang,
salin template ke folder `templates\` di sebelah EXE lalu edit. File di folder itu menang atas template bawaan.

### Batfish (opsional)

Pilih parser "Batfish" di tab Convert. Batfish dipakai untuk Cisco, Arista, Juniper, dan Fortinet
(vendor lain tidak didukung Batfish dan selalu memakai parser bawaan). Batfish adalah service Java
terpisah di `localhost:9996`. Java di laptop ini versi 8, terlalu lama untuk Batfish, jadi jalankan lewat Docker:

```
docker run -d -p 9996:9996 batfish/allinone
```

Mode "Batfish jika tersedia, lalu bawaan" otomatis kembali ke parser bawaan kalau service tidak jalan.

## Log Collector

- Tambah device manual atau import CSV (contoh: `inventory-example.csv`).
  Kolom: `host,ip,vendor,port,protocol,username,password`.
- Username/password kosong di CSV = memakai kredensial default di form.
- Export CSV **tidak pernah** menyimpan password.
- Command per vendor bisa diedit di panel kanan, tombol Simpan menulis `commands.json` di sebelah EXE.
- Hasil: `output\logs\<tanggal-jam>\<device>.log`. Output command konfigurasi juga disimpan di
  `configs\`, dan tombol **Kirim config ke Topologi** langsung menggambar topologi dari hasil itu.

## Topology Mapper

Drop beberapa file konfigurasi (atau satu folder) ke kanvas. Link dideteksi dari:

1. subnet IP yang sama (2 device = link point-to-point, lebih dari 2 = segmen LAN);
2. sesi BGP (alamat neighbor milik device lain yang dimuat), peer di luar file tampil sebagai node AS eksternal;
3. deskripsi interface yang menyebut hostname device lain (garis titik-titik).

Node bisa digeser dengan mouse, zoom dengan scroll, geser kanvas dengan klik kanan.
Export ke SVG, draw.io (bisa diedit di diagrams.net offline), atau CSV daftar link.

## Bulk Ping

- Target satu per baris (atau dipisah koma/spasi): IP, hostname, subnet (`192.168.1.0/24`), range
  (`10.0.0.1-50` atau `10.0.0.1-10.0.0.50`), atau baris CSV `NAMA,IP`. Bisa drop file .txt/.csv atau
  ambil dari inventory tab Log Collector. Maksimum 4096 target per jalan.
- Opsi: jumlah ping, timeout, ukuran paket, jumlah paralel, ulang otomatis tiap N detik, reverse DNS.
- Hasil: status UP / DOWN / PARTIAL / ERROR, loss, RTT min/avg/max, TTL. Klik judul kolom untuk sort,
  filter per status, export CSV.
- Memakai perintah `ping` Windows, jadi tidak butuh hak administrator dan bekerja di Windows bahasa apa pun.

## Speed Test

| Mode | Kebutuhan | Kegunaan |
|---|---|---|
| Internet (Cloudflare) | koneksi internet | kecepatan internet ke server speed.cloudflare.com terdekat |
| URL server sendiri | web server dengan file besar | throughput ke server internal (download; upload jika server menerima POST) |
| LAN ke NetManage lain | NetManage di laptop kedua, offline | throughput link antar site/VLAN, mirip iperf |

Untuk mode LAN: di laptop kedua buka tab Speed Test, klik **Jalankan server** (port default 5201,
izinkan di Windows Firewall jika diminta). Di laptop pertama pilih mode LAN, isi IP laptop kedua, lalu
**Mulai speed test**. Hasil: ping, jitter, download, upload (Mbps). Detik pertama tiap arah tidak dihitung
(pemanasan TCP). Riwayat bisa di-export CSV.

## Test

```
.venv\Scripts\python tests\test_matrix.py      # 10 sample x 10 vendor tujuan, cek round-trip
.venv\Scripts\python tests\test_policy.py      # route-map, ACL, QoS: 10 sample x 10 vendor, round-trip
.venv\Scripts\python tests\test_tools.py       # topologi + collector (koneksi palsu)
.venv\Scripts\python tests\test_nettools.py    # bulk ping + speed test LAN (loopback) + tab GUI
.venv\Scripts\python tests\test_i18n.py        # semua teks UI punya terjemahan Inggris
.venv\Scripts\python tests\screenshots.py out  # render semua tab (terang/gelap, ID/EN) ke PNG
.venv\Scripts\python tests\test_gui_smoke.py   # GUI tanpa mainloop
```

## Batasan

- NAT, VPN/IPsec, MPLS, IPv6 ACL, as-path list, community-list expanded (regex), dan ACL berbasis
  object-group/address-list tidak dikonversi; semuanya tercantum di laporan.
- Semantik yang beda antar platform didekati, bukan disalin 1:1. Contoh: route-filter Junos memakai
  longest-match (Cisco prefix-list first-match); di MikroTik police dan shape sama-sama menjadi
  `max-limit` queue tree; Fortinet stateful sehingga `established` diabaikan.
- Hasil konversi route-map, ACL, dan QoS wajib diuji di lab sebelum dipasang di produksi.
- Nama port fisik dipetakan berdasarkan urutan nomor. Sesuaikan dengan hardware tujuan.
- Hash password user lokal tidak bisa dipindah antar vendor, jadi user tidak dikonversi.
- Parser dan collector diuji dengan sample sintetis di `samples/` dan koneksi palsu, belum dengan device fisik.
