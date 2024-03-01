rule SIGNATURE_BASE_Goldeneye_Ransomware_XLS : FILE
{
	meta:
		description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
		author = "Florian Roth (Nextron Systems)"
		id = "6eafcc35-56ef-534f-884a-0bb47c27c274"
		date = "2016-12-06"
		modified = "2023-12-05"
		reference = "https://goo.gl/jp2SkT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_goldeneye.yar#L10-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "827c1d1c0f9c3ebd77413de7e1db5e29d05f2ece6676c79a79f6c1ff2788f42b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"

	strings:
		$x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
		$x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <4000KB and 1 of them )
}
