rule SIGNATURE_BASE_Xscanlib : FILE
{
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "e1e2cfad-7cbb-51c3-9b55-648c47af641e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L386-L402"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		logic_hash = "ff18c527df9ff2a4d72bcc5e4905d6f42877d42536edcb13608c6e0e6773aa63"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "XScanLib.dll" fullword ascii
		$s6 = "Ports/%s/%d" fullword ascii
		$s8 = "DEFAULT-TCP-PORT" fullword ascii
		$s9 = "PlugCheckTcpPort" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <360KB and all of them
}
