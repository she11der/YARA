rule SIGNATURE_BASE_Sphinx_Moth_Nvcplex : FILE
{
	meta:
		description = "sphinx moth threat group file nvcplex.dat"
		author = "Kudelski Security - Nagravision SA"
		id = "dd1b4071-adf5-5d54-9b4c-877f0965bdc7"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "www.kudelskisecurity.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sphinx_moth.yar#L106-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2f851c0ab8c4a426b00addfbe0da7ceebb08e93014efcb11d64247d14fec909b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "mshtaex.exe" fullword wide
		$op0 = { 41 8b cc 44 89 6c 24 28 48 89 7c 24 20 ff 15 d3 }
		$op1 = { 48 3b 0d ad 8f 00 00 74 05 e8 ba f5 ff ff 48 8b }
		$op2 = { 8b ce e8 49 47 00 00 90 8b 43 04 89 05 93 f1 00 }

	condition:
		uint16(0)==0x5a4d and filesize <214KB and all of them
}
