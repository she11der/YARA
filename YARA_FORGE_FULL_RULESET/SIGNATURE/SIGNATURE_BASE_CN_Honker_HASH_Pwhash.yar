rule SIGNATURE_BASE_CN_Honker_HASH_Pwhash : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file pwhash.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5d8c3648-a725-5f01-9800-b75b8c740cf1"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1896-L1911"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "689056588f95749f0382d201fac8f58bac393e98"
		logic_hash = "a77ae11c35dac3cfb1a2970460d4883feed7fbd3e8a860fa7facaad7ddcd1182"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Example: quarks-pwdump.exe --dump-hash-domain --with-history" fullword ascii
		$s2 = "quarks-pwdump.exe <options> <NTDS file>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}
