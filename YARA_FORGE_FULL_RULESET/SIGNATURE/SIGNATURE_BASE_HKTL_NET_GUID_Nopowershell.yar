import "pe"

rule SIGNATURE_BASE_HKTL_NET_GUID_Nopowershell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0fd7496b-e34f-51f7-9270-ad424ed6a7a8"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/bitsadmin/nopowershell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_github_net_redteam_tools_guids.yar#L282-L296"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "29ce3eaf0eca016fd72b54c8773226102cabcfd65d172e42fffe1c29e79d16ec"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii wide
		$typelibguid0up = "555AD0AC-1FDB-4016-8257-170A74CB2F55" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
