rule SIGNATURE_BASE_Blackenergy_Killdisk_2 : FILE
{
	meta:
		description = "Detects KillDisk malware from BlackEnergy"
		author = "Florian Roth (Nextron Systems)"
		id = "f0304e87-a278-5963-9af0-935c088c00ec"
		date = "2016-01-03"
		modified = "2023-01-06"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_blackenergy.yar#L117-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "38ce9ab347690914f27e7ae89cc6fb2af02ee223e21822eb3b75fde772d3eaff"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
		hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
		hash3 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"

	strings:
		$s0 = "%c:\\~tmp%08X.tmp" fullword ascii
		$s1 = "%s%08X.tmp" fullword ascii
		$s2 = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" wide
		$s3 = "%ls_%ls_%ls_%d.~tmp" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 3 of them
}
