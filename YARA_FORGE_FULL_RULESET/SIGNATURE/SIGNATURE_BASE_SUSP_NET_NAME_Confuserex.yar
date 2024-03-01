rule SIGNATURE_BASE_SUSP_NET_NAME_Confuserex : FILE
{
	meta:
		description = "Detects ConfuserEx packed file"
		author = "Arnim Rupp"
		id = "f1bda14e-c9fe-5341-8962-691a66233eb0"
		date = "2021-01-22"
		modified = "2021-01-25"
		reference = "https://github.com/yck1509/ConfuserEx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_github_net_redteam_tools_names.yar#L219-L234"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "beecb7b66830a033e2048da246d320c1ffc5015b280b34fb61aee87c8a42fff3"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "ConfuserEx" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
