rule SIGNATURE_BASE_Goodtoolset_Ms11080 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ms11080.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "080e04a3-5cbe-57a8-9106-539451922cb4"
		date = "2015-06-13"
		modified = "2022-12-21"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2398-L2417"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
		logic_hash = "a5b03dded6146dae48bca962e7c5419c2ea69f8709ae7f2c9355bd178d5d77fb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "\\ms11080\\Debug\\ms11080.pdb" ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[*] Add to Administrators success" fullword ascii
		$s5 = "[*] User has been successfully added" fullword ascii
		$s6 = "[>] ms11-08 Exploit" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 2 of them
}
