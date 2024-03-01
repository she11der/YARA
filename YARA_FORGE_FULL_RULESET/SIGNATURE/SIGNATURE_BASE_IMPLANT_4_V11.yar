import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V11 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "e5fb0843-20f7-56a0-8eea-0db7cef7f610"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L968-L985"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7bdeddc4334ed6557175b5eefc78d69283d6c91f98970bd0cfe6365b3ab477f4"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$ = "/c format %c: /Y /X /FS:NTFS"
		$ = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" wide
		$ = ".dll.exe.xml.ttf.nfo.fon.ini.cfg.boot.jar" wide
		$ = ".crt.bin.exe.db.dbf.pdf.djvu.doc.docx.xls.xlsx.jar.ppt.pptx.tib.vhd.iso.lib.mdb.accdb.sql.mdf.xml.rtf.ini.cf g.boot.txt.rar.msi.zip.jpg.bmp.jpeg.tiff" wide
		$tempfilename = "%ls_%ls_%ls_%d.~tmp" ascii wide

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and 2 of them
}
