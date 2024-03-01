rule SIGNATURE_BASE_Karmasmb : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "32c810c7-02e7-5203-b2ed-4e930b318cc0"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L93-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "94322dda799bcb25caeb7f9e526bcc14c6dfd9247080b4bb79dcd7b340fcb36c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"

	strings:
		$s1 = "bkarmaSMB.exe.manifest" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
