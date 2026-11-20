# PyInstaller spec for NetManage. Build: .venv\Scripts\pyinstaller NetManage.spec --noconfirm
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = [("netmanage/templates", "netmanage/templates"), ("netmanage/assets", "netmanage/assets"),
         ("samples", "samples")]
datas += collect_data_files("tkinterdnd2")
datas += collect_data_files("sv_ttk")
datas += collect_data_files("netmiko")
datas += collect_data_files("pybatfish")
hidden = collect_submodules("netmiko") + collect_submodules("netmanage") + collect_submodules("pybatfish")

a = Analysis(
    ["app.py"],
    pathex=["."],
    datas=datas,
    hiddenimports=hidden,
    excludes=["matplotlib", "IPython", "pytest", "jupyter", "notebook", "PIL"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="NetManage",
    console=False,
    upx=False,
    icon="netmanage/assets/icon.ico",
)
