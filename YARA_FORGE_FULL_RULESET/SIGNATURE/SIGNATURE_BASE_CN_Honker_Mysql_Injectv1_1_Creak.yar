rule SIGNATURE_BASE_CN_Honker_Mysql_Injectv1_1_Creak : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mysql_injectV1.1_Creak.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "39025a57-557a-53c0-bfdb-81fe83f824af"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L66-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a1f066789f48a76023598c5777752c15f91b76b0"
		logic_hash = "f61557216a7e90ff9655ad8aea4a9adf0e4435c7a3f7958423e46fd2265bad07"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "1http://192.169.200.200:2217/mysql_inject.php?id=1" fullword ascii
		$s12 = "OnGetPassword" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5890KB and all of them
}
