rule SIGNATURE_BASE_CN_Tools_Xbat : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xbat.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "5b2f0d2e-a7fb-5f5a-94a9-28e851c9756e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktool_scripts.yar#L10-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a7005acda381a09803b860f04d4cae3fdb65d594"
		logic_hash = "c6dae76bbda7b43eef348c61e1330405923baf724f1aa5d2b51132dde89248fe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ws.run \"srss.bat /start\",0 " fullword ascii
		$s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii

	condition:
		uint16(0)==0x6553 and filesize <0KB and all of them
}
